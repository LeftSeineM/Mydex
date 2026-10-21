"""JSON-lines subprocess adapter for headless Web WeChat. No GUI dependencies."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import base64
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time

from lab import ROOT, NO_WINDOW, UserError


class ProtocolBridge:
    def __init__(self, engine):
        self.engine = engine
        self.lock = threading.RLock()
        self.write_lock = threading.Lock()
        self.process = None
        self.stop_event = threading.Event()
        self.qr = None
        self.draft_targets = {}
        self.status = dict(running=False, phase='unavailable', message='群收发尚未接通。网页版实验及导致崩溃的原生探针已停用；正在离线分析客户端。Codex 后端可单独测试。', mode='preview', transport='web_protocol', logged_in=False)

    def state(self):
        with self.lock:
            return {**self.status, 'running': bool(self.process and self.process.poll() is None), 'has_qr': self.qr is not None,
                    'web_research_enabled': os.getenv('WECHAT_LAB_ENABLE_WEB_RESEARCH') == '1'}

    def set_status(self, **values):
        with self.lock:
            self.status.update(values)

    def command(self, data):
        with self.write_lock:
            if not self.process or self.process.poll() is not None:
                raise UserError('协议进程未运行，请重新扫码')
            self.process.stdin.write(json.dumps(data, ensure_ascii=False) + '\n')
            self.process.stdin.flush()

    def start(self, auto_send=False):
        if os.getenv('WECHAT_LAB_ENABLE_WEB_RESEARCH') != '1':
            raise UserError('网页版实验已停用；当前缺少可用的非网页通道，请勿重复扫码')
        with self.lock:
            if self.state()['running']:
                raise UserError('协议通道已运行；重新扫码前请先停止')
            node = shutil.which('node')
            dep = Path(os.getenv('WECHAT_LAB_PROTOCOL_DIR', configured_path('runtime', 'protocol/node_modules')))
            if not node or not (dep / 'wechat4u/lib/core.js').is_file():
                raise UserError('缺少 Node 或 D 盘微信协议依赖')
            self.stop_event = threading.Event()
            self.qr = None
            self.draft_targets = {}
            self.status.update(phase='connecting', message='正在启动无界面消息协议…', mode='auto' if auto_send else 'preview', logged_in=False)
            # No debug logs: dependency errors can contain session cookies and HTTP payloads.
            env = {**os.environ, 'DEBUG': '', 'NODE_DEBUG': ''}
            self.process = subprocess.Popen([node, str(ROOT / 'protocol_worker.cjs')], cwd=ROOT,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding='utf-8', bufsize=1, creationflags=NO_WINDOW, env=env)
            jobs = queue.Queue(maxsize=16)
            self.command({'type': 'start', 'group': self.engine.settings.get()['group'], 'bot_name': self.engine.settings.get()['bot_name']})
            threading.Thread(target=self.read, args=(self.process, self.stop_event, jobs), daemon=True).start()
            threading.Thread(target=self.work, args=(self.stop_event, jobs, auto_send), daemon=True).start()

    def read(self, process, stopped, jobs):
        try:
            for line in process.stdout:
                if stopped.is_set(): break
                event = json.loads(line)
                kind = event.get('type')
                if kind == 'qr':
                    data = base64.b64decode(event['data'], validate=True)
                    if len(data) <= 512000 and event['mime'] in ('image/jpeg','image/png','image/gif'):
                        with self.lock:
                            self.qr = (data, event['mime'])
                            self.status['qr_expires_at'] = event['expires_at']
                elif kind == 'clear_qr':
                    with self.lock: self.qr = None
                elif kind == 'status':
                    self.set_status(**{k:v for k,v in event.items() if k in ('phase','message','logged_in','account_name','mention_name')})
                    if event.get('phase') == 'error':
                        with self.lock: self.qr = None
                elif kind == 'message':
                    try: jobs.put_nowait(event)
                    except queue.Full: self.set_status(message='消息队列已满，本条未交给模型')
                elif kind == 'sent':
                    self.engine.store.transition(event['id'], 'sending', 'sent' if event.get('ok') else 'unknown')
                    self.set_status(message='微信协议报告发送成功' if event.get('ok') else '发送结果不确定，请在群里核对；不会自动重发')
        except Exception:
            self.set_status(phase='error', message='协议进程响应异常；已停止连接')
        finally:
            stopped.set()
            if process.poll() is None: process.terminate()
            for key in list(self.draft_targets): self.engine.store.transition(key, 'sending', 'unknown')
            with self.lock:
                self.qr = None
                self.status['logged_in'] = False
                if self.status['phase'] != 'error': self.status.update(phase='stopped', message='协议连接已停止')

    def work(self, stopped, jobs, auto_send):
        while not stopped.is_set():
            try: event = jobs.get(timeout=0.5)
            except queue.Empty: continue
            try:
                result = self.engine.process({**event, 'type':'text', 'source':'wechat'})
                if stopped.is_set(): continue
                key = result.get('draft_id')
                if key:
                    self.draft_targets[key] = event['room_id']
                    self.set_status(message='已收到目标群 @ 消息，回复已生成')
                    if auto_send: self.approve(key)
            except Exception as exc:
                self.set_status(message=str(exc)[:250] if isinstance(exc,UserError) else '消息处理失败：' + type(exc).__name__)

    def approve(self, key):
        if self.stop_event.is_set() or not self.state()['logged_in'] or key not in self.draft_targets:
            raise UserError('此草稿不属于当前已登录的协议会话，不能发送')
        draft = next((d for d in self.engine.store.pending() if d['id']==key and d['state']=='draft'), None)
        if not draft or draft['room'] != self.engine.settings.get()['group']:
            raise UserError('草稿不属于当前测试群')
        if not self.engine.store.transition(key, 'draft', 'sending'): return
        try: self.command(dict(type='send', id=key, room_id=self.draft_targets[key], content=draft['content']))
        except Exception:
            self.engine.store.transition(key, 'sending', 'unknown')
            raise UserError('发送结果不确定，请手动核对') from None

    def stop(self):
        self.stop_event.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.set_status(phase='stopped', message='协议连接已停止', logged_in=False)
        with self.lock: self.qr = None

    def qr_image(self):
        with self.lock:
            if self.status.get('qr_expires_at', 0) < time.time(): return None
            return self.qr
