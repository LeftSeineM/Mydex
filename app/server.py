"""Loopback-only research console. Python stdlib; no frontend build step."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse, parse_qs
import uuid

from lab import DATA, ROOT, Settings, Store, Engine, UserError, codex_status
from protocol_bridge import ProtocolBridge
from native_inbox import NativeInbox
from database_inbox import DatabaseInbox
from native_sender_bridge import NativeSender
from group_scopes import scopes, GroupSettings


def native_observer_state():
    path = DATA / ('native-trace.json' if (DATA/'native-trace.json').exists() else 'native-observer.json')
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
        if raw.get('fixture'):
            raise ValueError('Fixture report is not a client connection')
        result = {key: raw.get(key) for key in ('pid', 'phase', 'running', 'calls', 'matches', 'read_errors', 'at')}
        result['stale'] = time.time() - path.stat().st_mtime > 12
        result['running'] = raw.get('running') is True
        return result
    except (OSError, ValueError, TypeError):
        return {'running': False, 'phase': 'unavailable', 'stale': True}


def stop_native_observer():
    state = native_observer_state()
    pid = state.get('pid')
    if not isinstance(pid, int) or pid <= 0:
        raise UserError('没有已记录的微信观察进程')
    script='research/trace_v7/run.py' if (DATA/'native-trace.json').exists() else 'research/run_native_observer.py'
    result = subprocess.run([sys.executable, str(ROOT / script),
                             '--pid', str(pid), '--stop'], capture_output=True, text=True,
                            timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise UserError('停止未确认，请检查微信进程和本地观察器日志')
    return native_observer_state()

def native_receiver_state():
    path=DATA/'native-receiver.json'
    try:
        raw=json.loads(path.read_text(encoding='utf-8'))
        if raw.get('fixture'):raise ValueError('Fixture report')
        result={k:raw.get(k) for k in ('pid','phase','running','calls','captured','read_errors','dropped','oversize','decode_rejections','receive_verified','at')}
        result['stale']=time.time()-path.stat().st_mtime>12
        result['running']=raw.get('running') is True
        return result
    except (OSError,ValueError,TypeError):return {'running':False,'stale':True,'receive_verified':False}

def stop_native_receiver():
    pid=native_receiver_state().get('pid')
    if not isinstance(pid,int) or pid<=0:raise UserError('没有已记录的接收观察进程')
    result=subprocess.run([sys.executable,str(ROOT/'research/run_native_receiver.py'),'--pid',str(pid),'--stop'],
                          capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise UserError('接收停止未确认，请检查本地日志')
    return native_receiver_state()


class Application:
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.settings = Settings()
        self.store = Store()
        self.engine = Engine(self.settings, self.store)
        self.inbox = NativeInbox(self.engine)
        self.native_sender = NativeSender(self.engine)
        self.database_inbox = DatabaseInbox(self.engine, sender=self.native_sender)
        self.group_inboxes = [self.database_inbox]
        self.monitoring_waiting_for_binding = True
        self.group_scopes = scopes(self.settings)
        for entry in self.group_scopes:
            if entry['configured_name'] == self.settings.get()['group']:continue
            group_engine=Engine(GroupSettings(self.settings,entry),self.store)
            since=entry.get('added_at',(DATA/'monitored-groups.json').stat().st_mtime)
            self.group_inboxes.append(DatabaseInbox(group_engine,sender=self.native_sender,scope=entry['room_id'],initial_since=since))
        self.bridge = ProtocolBridge(self.engine)
        self.jobs = {}
        self.lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(8)
        self.pool = ThreadPoolExecutor(max_workers=1)
        self.codex = codex_status()
        self.probe = {"connected": False, "error": "原生接收与发送研究中，真实群回复尚未接通"}

    def submit(self, fn):
        if not self.slots.acquire(blocking=False):
            raise UserError("待处理任务较多，请稍后再试")
        key = uuid.uuid4().hex
        with self.lock:
            self.jobs[key] = {"status": "pending", "created": time.time()}
            if len(self.jobs) > 100:
                done = [k for k, v in self.jobs.items() if v["status"] in ("done", "error")]
                for old in done[:len(self.jobs) - 100]:
                    del self.jobs[old]
        def work():
            try:
                with self.lock:
                    self.jobs[key]["status"] = "running"
                result = fn()
                with self.lock:
                    self.jobs[key].update(status="done", result=result)
            except Exception as exc:
                message = str(exc) if isinstance(exc, UserError) else "处理失败：" + type(exc).__name__
                with self.lock:
                    self.jobs[key].update(status="error", error=message)
            finally:
                self.slots.release()
        self.pool.submit(work)
        return {"job_id": key}

    def diagnostics(self):
        self.codex = codex_status()
        bridge = self.bridge.state()
        self.probe = {"connected": bridge.get("logged_in", False), "error": bridge["message"]}
        DATA.mkdir(exist_ok=True)
        report = {"checked_at": time.time(), "codex": self.codex, "wechat": self.probe}
        (DATA / "diagnostics.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return report

    def state(self):
        cfg = self.settings.get(public=True)
        _, coverage = self.store.context('wechat', cfg['group'], cfg['summary_messages'], cfg['summary_max_chars'])
        from member_labels import display_sender
        rows=self.store.history('wechat',cfg['group'],80)
        visible=[{**r,'sender':display_sender(r['sender'],cfg['group'])} for r in rows]
        return {"settings": cfg, "codex": self.codex, "wechat_probe": self.probe,
                'native_inbox': self.inbox.state(), 'database_inbox': self.database_inbox.state(), 'record_scope': coverage,
                'native_sender': self.native_sender.state(),
                'group_states': [inbox.state() for inbox in self.group_inboxes],
                'monitored_groups': self.group_scopes,
                'monitoring_waiting_for_binding': self.monitoring_waiting_for_binding,
                "bridge": self.bridge.state(), "outbox": self.store.pending(),
                "simulation": self.store.history("simulation", cfg["group"], 80),
                "wechat": visible}


def handler_for(app, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Do not write group text, tokens, or keys to request logs.

        def host_valid(self):
            return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def reply(self, value, status=200, mime="application/json; charset=utf-8"):
            body = json.dumps(value, ensure_ascii=False).encode("utf-8") if isinstance(value, (dict, list)) else value
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.host_valid():
                return self.reply({"error": "Host not allowed"}, 403)
            path = urlparse(self.path)
            if path.path == "/":
                html = (ROOT / "index.html").read_text(encoding="utf-8").replace("__CSRF_TOKEN__", app.token)
                return self.reply(html.encode("utf-8"), mime="text/html; charset=utf-8")
            if path.path == "/api/state":
                return self.reply(app.state())
            if path.path == "/api/health":
                # Liveness must not load history, invoke the model, or inspect
                # the native client. Binding checks still use /api/state.
                return self.reply({'service': 'wechat-group-lab', 'status': 'ok',
                                   'groups': [inbox.state() for inbox in app.group_inboxes]})
            if path.path == "/api/native/status":
                return self.reply(native_observer_state())
            if path.path == '/api/native/receive':
                return self.reply(native_receiver_state())
            if path.path == "/api/wechat/qr":
                qr = app.bridge.qr_image()
                if not qr:
                    return self.reply({"error": "二维码尚未生成或已过期"}, 404)
                return self.reply(qr[0], mime=qr[1])
            if path.path == "/api/job":
                key = parse_qs(path.query).get("id", [""])[0]
                with app.lock:
                    job = app.jobs.get(key)
                    return self.reply(dict(job) if job else {"error": "任务不存在"}, 200 if job else 404)
            return self.reply({"error": "Not found"}, 404)

        def do_POST(self):
            if not self.host_valid() or not secrets.compare_digest(self.headers.get("X-Lab-Token", ""), app.token):
                return self.reply({"error": "仅允许本机研究面板发起操作"}, 403)
            origin = self.headers.get("Origin")
            if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
                return self.reply({"error": "Origin not allowed"}, 403)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise UserError("请求大小无效")
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise UserError("请求必须为 JSON 对象")
                if self.path == "/api/settings":
                    if app.bridge.state()["running"]:
                        raise UserError("请先停止微信监听，再修改配置")
                    return self.reply(app.settings.update(data))
                if self.path == "/api/native/stop":
                    return self.reply(stop_native_observer())
                if self.path == '/api/native/receive/stop':
                    return self.reply(stop_native_receiver())
                if self.path == '/api/history/stop':
                    app.monitoring_waiting_for_binding=False
                    for inbox in app.group_inboxes:inbox.stop()
                    return self.reply(app.database_inbox.state())
                if self.path == '/api/history/start':
                    if not app.native_sender.state(fresh=True)['connected']:
                        raise UserError('请先验证当前电脑微信会话；不会沿用旧账号自动监听')
                    app.monitoring_waiting_for_binding=False
                    for inbox in app.group_inboxes:inbox.start()
                    return self.reply(app.database_inbox.state())
                if self.path == '/api/history/summary':
                    return self.reply(app.submit(app.engine.summarize_history),202)
                if self.path == '/api/history/retry-at':
                    return self.reply(app.submit(lambda:app.database_inbox.retry_mention(str(data.get('id','')))),202)
                if self.path == '/api/native/send':
                    return self.reply(app.submit(lambda:app.native_sender.send_draft(str(data.get('id','')))),202)
                if self.path == '/api/native/sending':
                    return self.reply(app.native_sender.set_enabled(data.get('enabled')))
                if self.path == '/api/native/bind':
                    state=app.native_sender.bind_session(data.get('pid'),data.get('process_created'))
                    if app.monitoring_waiting_for_binding:
                        for inbox in app.group_inboxes:inbox.start()
                        app.monitoring_waiting_for_binding=False
                    return self.reply(state)
                if self.path == "/api/simulate":
                    # Simulation can never select a real channel or invoke WeChat sending.
                    event = {k: data[k] for k in ("sender", "content", "id", "is_self") if k in data}
                    event.update(source="simulation", room=app.settings.get()["group"])
                    return self.reply(app.submit(lambda: app.engine.process(event)), 202)
                if self.path == "/api/diagnostics":
                    if app.bridge.state()["running"]:
                        raise UserError("请先停止微信监听，再进行兼容性探测")
                    return self.reply(app.submit(app.diagnostics), 202)
                if self.path == "/api/bridge/start":
                    app.bridge.start(auto_send=data.get("auto_send") is True)
                    return self.reply(app.bridge.state())
                if self.path == "/api/bridge/stop":
                    app.bridge.stop()
                    return self.reply(app.bridge.state())
                if self.path == "/api/outbox/send":
                    app.bridge.approve(str(data.get("id", "")))
                    return self.reply({"status": "queued"})
                return self.reply({"error": "Not found"}, 404)
            except (UserError, ValueError, TypeError) as exc:
                return self.reply({"error": str(exc)[:400]}, 400)
            except Exception as exc:
                return self.reply({"error": "操作失败：" + type(exc).__name__}, 500)
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8769)
    args = parser.parse_args()
    app = Application()
    # Native observer remains an independent proof source. Only the database
    # inbox invokes the model, avoiding two consumers racing on the same @.
    if app.native_sender.enabled and app.native_sender.state(fresh=True)['connected']:
        for inbox in app.group_inboxes:inbox.start()
        app.monitoring_waiting_for_binding=False
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(app, args.port))
    print(f"WeChat Group Lab: http://127.0.0.1:{args.port}", flush=True)
    print("Monitoring waits for a verified client session; send limits and failure protection are enabled.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.inbox.stop()
        for inbox in app.group_inboxes:inbox.stop()
        app.bridge.stop()
        server.server_close()
        app.pool.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
