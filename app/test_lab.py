import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess

from lab import Backend, Engine, Settings, Store, UserError, codex_args
from wechat_bridge import SnapshotCursor, WeChatBridge
from server import Application, handler_for
from protocol_bridge import ProtocolBridge


class CapturingBackend:
    def __init__(self):
        self.calls = []

    def reply(self, cfg, messages):
        self.calls.append(messages)
        return "已收到，测试回复。"


class LabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(self.root / "settings.json")
        self.store = Store(self.root / "history.db")
        self.backend = CapturingBackend()
        self.engine = Engine(self.settings, self.store, self.backend)

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def event(self, **kwargs):
        return dict({"id": "one", "room": "AI助手测试群", "sender": "研究员 A", "content": "@小研 你好", "source": "simulation"}, **kwargs)

    def test_at_trigger_and_dedup(self):
        self.assertEqual(self.engine.process(self.event())["status"], "replied")
        self.assertEqual(self.engine.process(self.event())["status"], "duplicate")
        self.assertEqual(len(self.backend.calls), 1)

    def test_filters_do_not_call_model(self):
        cases = [{"content": "今天的天气不错"}, {"content": "@小研二号 你好"},
                 {"sender": "小研"}, {"is_self": True}, {"attr": "system"},
                 {"room": "其他群"}, {"type": "image"}]
        for index, case in enumerate(cases):
            self.assertEqual(self.engine.process(self.event(id=str(index), **case))["status"], "ignored")
        self.assertFalse(self.backend.calls)

    def test_unicode_wechat_mention_separator(self):
        self.assertEqual(self.engine.process(self.event(content="@小研\u2005你好"))["status"], "replied")

    def test_sources_and_rooms_are_isolated(self):
        self.engine.process(self.event(content="@小研 模拟秘密"))
        result = self.engine.process(self.event(source="wechat", content="@小研 真实消息"))
        self.assertNotIn("模拟秘密", json.dumps(self.backend.calls[-1], ensure_ascii=False))
        self.assertIn("draft_id", result)
        self.settings.update({"group": "第二测试群"})
        self.engine.process(self.event(room="第二测试群", content="@小研 第二群消息"))
        self.assertNotIn("模拟秘密", json.dumps(self.backend.calls[-1], ensure_ascii=False))

    def test_summary_includes_ordinary_discussion_without_model_calls(self):
        first = self.engine.process(self.event(id='ordinary', content='M 负责周五交付方案'))
        self.assertTrue(first['recorded'])
        self.assertFalse(self.backend.calls)
        result = self.engine.process(self.event(id='summary', content='@小研 总结群聊待办'))
        context = json.dumps(self.backend.calls[-1], ensure_ascii=False)
        self.assertIn('周五交付方案', context)
        self.assertEqual(result['record_scope']['included_messages'], 2)
        self.assertEqual(result['record_scope']['history_completeness'], 'unknown')

    def test_imported_old_mentions_do_not_reply_and_deduplicate_live(self):
        event = self.event(id='past', source='wechat', content='@小研 去年的旧提问', created=1700000000)
        self.assertEqual(self.engine.record_history([event]), {'added': 1, 'skipped': 0, 'replies_created': 0})
        self.assertFalse(self.backend.calls)
        self.assertFalse(self.store.pending())
        self.assertEqual(self.engine.process(event)['status'], 'duplicate')
        self.engine.process(self.event(id='now', source='wechat', content='@小研 总结聊天记录'))
        self.assertIn('旧提问', json.dumps(self.backend.calls[-1], ensure_ascii=False))

    def test_history_import_checks_room_source_identity_and_time(self):
        base = self.event(source='wechat', created=1700000000)
        bad = [{**base, 'room': '其他群'}, {**base, 'source': 'simulation'},
               {**base, 'id': ''}, {**base, 'created': float('nan')}, {**base, 'type': 'image'}]
        self.assertEqual(self.engine.record_history(bad)['added'], 0)
        self.assertFalse(self.store.history('wechat', 'AI助手测试群'))

    def test_summary_reports_omitted_records_and_room_isolation(self):
        for index in range(30):
            self.store.add('simulation', 'AI助手测试群', 'A', '讨论' * 300, 'user', str(index), 1700000000+index)
        self.store.add('wechat', 'AI助手测试群', 'A', '其他来源秘密', 'user', 'secret')
        rows, scope = self.store.context('simulation', 'AI助手测试群', 20, 4000)
        self.assertTrue(scope['older_messages_omitted'])
        self.assertLess(scope['included_messages'], 20)
        self.assertEqual(scope['stored_messages'], 30)
        self.assertNotIn('其他来源秘密', json.dumps(rows, ensure_ascii=False))

    def test_api_key_is_not_returned(self):
        self.settings.update({"api_key": "test-secret"})
        public = self.settings.get(public=True)
        self.assertNotIn("api_key", public)
        self.assertTrue(public["has_api_key"])

    def test_protocol_does_not_send_drafts_from_an_old_session(self):
        bridge = ProtocolBridge(self.engine)
        bridge.status['logged_in'] = True
        key = self.store.draft('AI助手测试群', 'test')
        with patch.object(bridge, 'command') as send:
            with self.assertRaises(UserError): bridge.approve(key)
            send.assert_not_called()
        self.assertEqual(self.store.pending()[0]['state'], 'draft')

    def test_retired_web_route_cannot_start_from_stale_browser_tabs(self):
        bridge = ProtocolBridge(self.engine)
        with patch.dict('os.environ', {'WECHAT_LAB_ENABLE_WEB_RESEARCH': ''}), patch('protocol_bridge.subprocess.Popen') as spawn:
            with self.assertRaisesRegex(UserError, '网页版实验已停用'):
                bridge.start()
            spawn.assert_not_called()

    def test_protocol_send_failure_is_unknown_and_not_retried(self):
        bridge = ProtocolBridge(self.engine)
        bridge.status['logged_in'] = True
        key = self.store.draft('AI助手测试群', 'test')
        bridge.draft_targets[key] = '@@test'
        with patch.object(bridge, 'command', side_effect=OSError) as send:
            with self.assertRaises(UserError): bridge.approve(key)
            with self.assertRaises(UserError): bridge.approve(key)
            self.assertEqual(send.call_count, 1)
        self.assertEqual(self.store.pending()[0]['state'], 'unknown')

    def test_cursor_no_history_replay_and_duplicate_text(self):
        cursor = SnapshotCursor()
        old = {"sender": "A", "content": "old", "attr": "friend", "type": "text"}
        new = {**old, "content": "@小研 hello"}
        self.assertEqual(cursor.update([old]), [])
        self.assertEqual(cursor.update([old, new]), [new])
        self.assertEqual(cursor.update([old, new]), [])
        self.assertEqual(cursor.update([old, new, new]), [new])
        self.assertEqual(cursor.update([{**old, "content": "different history"}]), [])

    def test_wrong_target_cannot_send(self):
        class FakeWeChat:
            def ChatInfo(self):
                return {"chat_type": "group", "chat_name": "其他群"}
            def SendMsg(self, text):
                raise AssertionError("must not send")
        bridge = WeChatBridge(self.engine)
        key = self.store.draft("AI助手测试群", "hello")
        with self.assertRaises(UserError):
            bridge.send(FakeWeChat(), "AI助手测试群", key)
        self.assertEqual(self.store.pending()[0]["state"], "draft")

    def test_stop_prevents_send(self):
        bridge = WeChatBridge(self.engine)
        bridge.stop()
        bridge.send(None, "AI助手测试群", self.store.draft("AI助手测试群", "hello"))
        self.assertEqual(self.store.pending()[0]["state"], "draft")

    def test_ambiguous_send_is_not_retried(self):
        class FakeWeChat:
            count = 0
            def ChatInfo(self):
                return {"chat_type": "group", "chat_name": "AI助手测试群"}
            def SendMsg(self, text):
                self.count += 1
                return None
        bridge, wx = WeChatBridge(self.engine), FakeWeChat()
        key = self.store.draft("AI助手测试群", "hello")
        bridge.send(wx, "AI助手测试群", key)
        bridge.send(wx, "AI助手测试群", key)
        self.assertEqual(wx.count, 1)
        self.assertEqual(self.store.pending()[0]["state"], "unknown")

    def test_codex_uses_stdin_and_disables_integrations(self):
        with patch("lab.codex_command", return_value=["codex.exe"]):
            args = codex_args(self.root)
        self.assertEqual(args[-1], "-")
        self.assertIn("--ignore-user-config", args)
        self.assertIn("read-only", args)
        self.assertIn("shell_tool", args)
        self.assertIn("plugins", args)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", args)

    def test_read_only_web_search_keeps_execution_and_apps_disabled(self):
        with patch('lab.codex_command',return_value=['codex.exe']):args=codex_args(self.root,web_search=True)
        self.assertIn('web_search="live"',args)
        pairs=list(zip(args,args[1:]))
        self.assertIn(('--disable','shell_tool'),pairs)
        self.assertIn(('--disable','code_mode'),pairs)
        self.assertIn(('--disable','apps'),pairs)
        self.assertNotIn(('--disable','code_mode_host'),pairs)

    def test_codex_not_logged_in_never_falls_back(self):
        with patch("lab.codex_status", return_value={"logged_in": False, "message": "CLI 未登录"}):
            with self.assertRaisesRegex(UserError, "未登录"):
                Backend().codex(self.settings.get(), [{"role": "user", "content": "hello"}])

    def test_codex_json_output_and_unicode_stdin(self):
        output = json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "中文回复"}}, ensure_ascii=False).encode()
        result = subprocess.CompletedProcess([], 0, output, b"")
        with patch("lab.codex_status", return_value={"logged_in": True}), patch("lab.codex_command", return_value=["codex.exe"]), patch("lab.DATA", self.root), patch("lab.subprocess.run", return_value=result) as runner:
            reply = Backend().codex(self.settings.get(), [{"role": "user", "content": "你好; $(do-not-execute)"}])
            self.assertEqual(reply, "中文回复")
            self.assertIn("你好", runner.call_args.kwargs["input"].decode())
            self.assertNotIn("你好", " ".join(runner.call_args.args[0]))
            self.assertFalse(runner.call_args.kwargs.get("shell", False))

    def test_api_real_http_request_to_local_stub(self):
        captured = []
        class Stub(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                captured.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                body = json.dumps({"choices": [{"message": {"content": "API 测试通过"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            cfg = {**self.settings.get(), "api_base": f"http://127.0.0.1:{server.server_port}/v1", "model": "stub", "api_key": ""}
            self.assertEqual(Backend().api(cfg, [{"role": "user", "content": "hello"}]), "API 测试通过")
            self.assertEqual(captured[0][0], "/v1/chat/completions")
            self.assertEqual(captured[0][1]["messages"][-1]["content"], "hello")
        finally:
            server.shutdown()
            server.server_close()


class ServerTests(unittest.TestCase):
    def test_native_report_excludes_group_identifier_and_fixture(self):
        from server import native_observer_state
        with tempfile.TemporaryDirectory() as folder, patch('server.DATA', Path(folder)):
            path = Path(folder) / 'native-observer.json'
            path.write_text(json.dumps({'fixture': False, 'running': True, 'pid': 123,
                                        'room_id_candidate': 'private@chatroom'}))
            state = native_observer_state()
            self.assertTrue(state['running'])
            self.assertFalse(state['stale'])
            self.assertNotIn('room_id_candidate', state)
            path.write_text(json.dumps({'fixture': True, 'running': True}))
            self.assertFalse(native_observer_state()['running'])

    def test_csrf_and_simulation_channel_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            cfg = Settings(Path(folder) / "settings.json")
            cfg.update({"provider": "mock"})
            store = Store(Path(folder) / "history.db")
            with patch("server.Settings", return_value=cfg), patch("server.Store", return_value=store), patch("server.codex_status", return_value={"logged_in": False}):
                app = Application()
            server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            server.RequestHandlerClass = handler_for(app, server.server_port)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{server.server_port}"
            payload = json.dumps({"source": "wechat", "sender": "A", "content": "@小研 hello"}).encode()
            try:
                with patch('server.stop_native_observer') as stopper:
                    with self.assertRaises(urllib.error.HTTPError) as native_error:
                        urllib.request.urlopen(urllib.request.Request(base + '/api/native/stop', b'{}'))
                    self.assertEqual(native_error.exception.code, 403)
                    stopper.assert_not_called()
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(urllib.request.Request(base + "/api/simulate", payload))
                self.assertEqual(error.exception.code, 403)
                request = urllib.request.Request(base + "/api/simulate", payload, {"X-Lab-Token": app.token})
                with urllib.request.urlopen(request) as response:
                    self.assertEqual(response.status, 202)
                app.pool.shutdown(wait=True)
                self.assertTrue(store.history("simulation", "AI助手测试群"))
                self.assertFalse(store.pending())
                request = urllib.request.Request(base + "/api/settings", b"{}", {"X-Lab-Token": app.token, "Origin": "https://evil.invalid"})
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request)
                self.assertEqual(error.exception.code, 403)
            finally:
                server.shutdown()
                server.server_close()
                store.db.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
