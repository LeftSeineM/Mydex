"""Group-bound native send queue with authenticated delivery checks.

Does not install hooks or reconnect. A restarted client requires a new binding.
Only linked real-WeChat drafts can use the native path. Unknown outcomes are
never retried automatically; old drafts are not replayed on startup.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time

from lab import DATA, UserError
from send_guard import SendGuard, SendHeld

class NativeSender:
    def __init__(self, engine, data=DATA, native_action=None, reader_factory=None):
        self.engine = engine
        self.data = Path(data)
        self.native_action = native_action
        self.reader_factory = reader_factory
        self.lock = threading.Lock()
        self.guard = SendGuard(engine.store, policy_path=self.data/'send-policy.json')
        self.enabled = False
        self.requested_enabled = False
        self.pid = None
        self.last = {'enabled': False, 'connected': False, 'sent': 0,
                     'message': '原生发送未启用'}
        self.checked = 0
        try:
            cfg = json.loads((self.data/'native-sender-settings.json').read_text(encoding='utf-8'))
            if isinstance(cfg.get('enabled'), bool) and isinstance(cfg.get('pid'), int) and cfg['pid'] > 0:
                proof = json.loads((self.data/'native-delivery-proof.json').read_text(encoding='utf-8'))
                if not proof.get('server_record_verified') or not proof.get('native_delivery_verified'):
                    raise ValueError('No authenticated send proof')
                if (proof.get('pid') != cfg['pid'] or proof.get('process_created') != cfg.get('process_created')
                        or not any(r.get('room_id') == cfg.get('group_id') for r in proof['matches'])):
                    raise ValueError('Wrong proof group')
                self.requested_enabled = cfg['enabled']
                self.enabled = cfg['enabled'] and cfg.get('account_verified') is True
                self.pid = cfg['pid']
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def action(self, command, body='', room=None):
        if self.native_action is not None:
            return self.native_action(self.pid, command, body)
        self.verify_session()
        config=json.loads((self.data/'native-sender-settings.json').read_text(encoding='utf-8'))
        if config.get('sender_version')==6:
            from research.worker_sender_v6.run import action
        elif config.get('sender_version')==5:
            from research.worker_sender_v5.run import action
        else:
            from research.worker_sender_v4.run import action
        return action(self.pid, command, body, room=room, data=self.data)

    def verify_session(self):
        import psutil
        config=json.loads((self.data/'native-sender-settings.json').read_text(encoding='utf-8'))
        if (config.get('pid') != self.pid or config.get('account_verified') is not True
                or config.get('process_created') != psutil.Process(self.pid).create_time()):
            raise UserError('当前微信会话尚未验证；请重新绑定账号，旧会话不能继续发送')

    def state(self, fresh=False):
        if not fresh and time.monotonic()-self.checked < 3:
            return dict(self.last)
        self.checked = time.monotonic()
        safety = self.guard.state()
        try:
            status = self.action('status') if self.pid else {}
            connected = bool(status.get('phase') == 2 and status.get('worker_thread'))
            self.last.update(enabled=self.enabled, connected=connected, pid=self.pid,
                             pending=status.get('pending', 0), executed=status.get('executed', 0),
                             message=('电脑微信原生发送已接通' if self.enabled else '自动发送已暂停') if connected else '原生发送未绑定，需检查电脑微信')
        except Exception as exc:
            self.last.update(enabled=self.enabled, connected=False, message='原生发送已断开：'+type(exc).__name__)
        self.last['send_guard'] = safety
        self.last['requested_enabled'] = self.requested_enabled
        if safety['blocked']:
            self.last['message'] = '自动发送已保护性暂停：'+safety['reason']
        return dict(self.last)

    def set_enabled(self, enabled):
        if not isinstance(enabled, bool):
            raise UserError('发送开关无效')
        if enabled:
            try:
                ready = self.action('status')
            except Exception:
                raise UserError('当前微信线程未绑定') from None
            if ready.get('phase') != 2 or not ready.get('worker_thread'):
                raise UserError('当前微信线程未绑定')
            self.guard.reset()
        self.enabled = enabled
        self.requested_enabled = enabled
        path=self.data/'native-sender-settings.json'
        previous=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
        path.write_text(json.dumps({**previous,'enabled': enabled, 'pid': self.pid}), encoding='utf-8')
        self.checked = 0
        return self.state(fresh=True)

    def bind_session(self, pid, created):
        """Accept a new session only after the local supervisor verifies it."""
        import psutil
        if not isinstance(pid,int) or pid<=0 or not isinstance(created,(int,float)):
            raise UserError('微信会话参数无效')
        config=json.loads((self.data/'native-sender-settings.json').read_text(encoding='utf-8'))
        if (config.get('pid')!=pid or config.get('process_created')!=created
                or config.get('account_verified') is not True or psutil.Process(pid).create_time()!=created):
            raise UserError('新微信会话尚未通过本机账号验证')
        with self.lock:
            previous=self.pid
            try:
                self.pid=pid
                native=self.action('status')
                if native.get('phase')!=2 or not native.get('worker_thread'):
                    raise UserError('新微信消息线程未绑定')
            except Exception:
                self.pid=previous
                raise
            self.enabled=config.get('enabled') is True
            self.requested_enabled=self.enabled
            self.checked=0
        return self.state(fresh=True)

    def reader(self, group=None):
        if self.reader_factory:
            return self.reader_factory()
        from history_reader import TargetHistory
        return TargetHistory(self.data,group=group)

    def allowed_targets(self):
        from group_scopes import scopes
        return {g['configured_name']:g['room_id'] for g in scopes(self.engine.settings,self.data)}

    def display_name(self, room):
        return self.engine.settings.get()['bot_name']

    def send_window_open(self):
        return True

    def send_draft(self, key):
        with self.lock:
            if not self.send_window_open():
                raise UserError('当前为静默时段，未发送回复草稿')
            if not self.enabled or not self.state(fresh=True)['connected']:
                raise UserError('微信原生发送当前未连接，草稿已保留')
            store = self.engine.store
            with store.lock:
                row = store.db.execute('SELECT * FROM outbox WHERE id=?', (key,)).fetchone()
                draft = dict(row) if row else None
            cfg = self.engine.settings.get()
            allowed=self.allowed_targets()
            if (not draft or draft['state'] != 'draft' or draft.get('source') != 'wechat'
                    or draft['room'] not in allowed or not draft.get('event_id')):
                raise UserError('只能发送当前绑定群的真实微信回复草稿')
            with store.lock:
                linked = store.db.execute('SELECT 1 FROM messages WHERE source=? AND room=? AND role=? AND event_id=? AND content=?',
                                          ('wechat', draft['room'], 'assistant', draft['event_id'], draft['content'])).fetchone()
            if not linked:
                raise UserError('草稿与真实群回复的关联未通过核对')
            body = self.display_name(draft['room'])+'：\n'+draft['content']
            if not 1 <= len(body.encode('utf-8')) <= 3072 or '\0' in body:
                raise UserError('回复超过单条原生发送长度，原文已保留在草稿')
            delay = self.guard.delay(draft)
            until = time.monotonic()+delay
            while time.monotonic() < until:
                if not self.enabled or not self.send_window_open():
                    raise SendHeld('自动发送已暂停；冷却中的草稿不会发送')
                time.sleep(max(0, min(.25, until-time.monotonic())))
            if not self.enabled or not self.send_window_open() or not self.state(fresh=True)['connected']:
                raise SendHeld('会话已断开或暂停；本条保留为草稿')
            reader = self.reader(draft['room'])
            if draft['room'] not in reader.aliases or reader.room != allowed.get(draft['room']):
                raise UserError('配置群与已验证发送群不一致')
            cursors = {path: reader.latest_cursor(path, draft['room']) for path in reader.message_paths()}
            if not self.enabled or not self.send_window_open():
                raise SendHeld('自动发送已暂停；本条保留为草稿')
            # Budget and dedup state survive process restart and native errors.
            self.guard.reserve(draft)
            if not store.transition(key, 'draft', 'sending'):
                self.guard.finish(key, 'cancelled')
                return {'status': 'already_claimed'}
            start = time.time()
            try:
                queued = self.action('send', body, room=reader.room)
                if queued.get('return_code') != 0:
                    raise UserError('微信发送队列未接受本条；自动发送已暂停，请人工检查')
                deadline = time.monotonic()+30
                while time.monotonic() < deadline:
                    for path, cursor in cursors.items():
                        result = reader.fetch(path, draft['room'], cursor)
                        for event in result['events']:
                            # The authenticated row must be beyond the pre-send cursor.
                            # Server timestamps can lag the Windows clock.
                            if (event.get('is_self') is True and event['content'] == body
                                    and event['id'].isdigit() and int(event['id'])):
                                store.transition(key, 'sending', 'sent')
                                self.guard.finish(key, 'sent')
                                proof = {'at': datetime.now(timezone.utc).isoformat(), 'draft_id': key,
                                         'request_event_id': draft['event_id'], 'reply_event_id': event['id'],
                                         'room_id': reader.room, 'server_record_verified': True}
                                (self.data/'native-reply-delivery.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
                                self.last.update(sent=self.last['sent']+1, last_draft_id=key,
                                                 last_reply_id=event['id'], message='回复已写入真实群记录')
                                return {'status': 'sent', 'draft_id': key, 'reply_event_id': event['id'], 'server_record_verified': True}
                        # A freshly inserted local message can receive its
                        # server_id in a later UPDATE. Keep the baseline cursor
                        # until verification completes so that update is seen.
                    time.sleep(.4)
                raise UserError('发送结果尚未核实；不会自动重发，请在群里核对')
            except Exception:
                store.transition(key, 'sending', 'unknown')
                self.guard.finish(key, 'unknown')
                self.guard.trip('发送失败或结果不明；核对微信状态与群记录后，手动恢复')
                self.checked = 0
                raise
