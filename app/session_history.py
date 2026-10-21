"""Account-isolated reader bound by the user's authenticated test message.

The display group name is user-confirmed; the room ID, sender ID and original
test server ID are independently checked in the account's authenticated DB.
"""
import hashlib
import json
from pathlib import Path
import re
from history_reader import TargetHistory, HistoryView, text_value
from lab import UserError


class SessionHistory(TargetHistory):
    def __init__(self, data, group=None):
        self.data = Path(data)
        session = json.loads((self.data/'session.json').read_text(encoding='utf-8'))
        self.room = session['allowed_room']
        if not re.fullmatch(r'\d{5,20}@chatroom', self.room):
            raise UserError('工作基地群标识无效')
        self.account_root = Path(session['account_roots'][0])
        if len(session['account_roots']) != 1:
            raise UserError('账号目录不唯一')
        match = re.fullmatch(r'(wxid_[A-Za-z0-9]+)_[0-9a-fA-F]{4}', self.account_root.name)
        if not match:
            raise UserError('账号目录无效')
        self.account = match.group(1)
        self.name = session['group']
        self.aliases = {self.name, 'Mydex测试群'}
        self.table = 'Msg_' + hashlib.md5(self.room.encode()).hexdigest()
        profile = json.loads((self.data/'history-file-profile.json').read_text(encoding='utf-8'))
        self.allowed = set()
        for item in profile:
            path = Path(item['parent'])/item['name']
            if self.account_root not in path.parents or path.name not in ('contact.db', 'message_0.db', 'message_1.db', 'message_2.db', 'message_3.db'):
                raise UserError('数据库路径与当前账号不一致')
            self.allowed.add(str(path))
        self.keys = {}
        self.history_since = 0
        self.refresh_keys()
        evidence = json.loads((self.data/'quote-sample-evidence.json').read_text(encoding='utf-8'))
        if evidence['account'] != self.account or evidence['room'] != self.room:
            raise UserError('测试样本属于其他账号或群')
        marker = session.get('verification_marker', '引用原文1008')
        sample = next((s for s in evidence['samples'] if s.get('type') == 1 and s.get('text') == marker), None)
        if not sample or not sample['server_id'].isdigit():
            raise UserError('缺少用户确认的原文测试样本')
        if session.get('verification_marker'):
            contact_paths = [p for p in self.keys if Path(p).name == 'contact.db']
            if len(contact_paths) != 1:
                raise UserError('联系人数据库未认证')
            key, salt = self.keys[contact_paths[0]]
            with HistoryView(contact_paths[0], key, salt) as view:
                rows = view.query('SELECT nick_name,is_in_chat_room FROM contact WHERE username=?', (self.room,))
            if len(rows) != 1 or rows[0][0] != self.name or not rows[0][1]:
                raise UserError('群名与当前账号联系人记录不一致')
        verified = False
        for path in self.message_paths():
            key, salt = self.keys[path]
            with HistoryView(path, key, salt) as view:
                if not view.query('SELECT name FROM sqlite_master WHERE name=?', (self.table,)):
                    continue
                rows = view.query('SELECT n.user_name,m.message_content,m.compress_content,m.create_time FROM "'+self.table+'" m LEFT JOIN Name2Id n ON n.rowid=m.real_sender_id WHERE m.server_id=? AND m.local_type=1', (int(sample['server_id']),))
                for sender, body, compressed, created in rows:
                    content = text_value(body) or text_value(compressed)
                    if content.startswith(self.account+':\n'):
                        content = content[len(self.account)+2:]
                    if sender == self.account and content == sample['text'] and created >= session.get('enrollment_started', 0):
                        verified = True
        if not verified:
            raise UserError('当前账号的工作基地测试消息未通过认证')
        if group is not None and group not in self.aliases:
            requested={'水群-深圳实践':'90000000002@chatroom','因为我们是无44！':'90000000004@chatroom'}
            if group not in requested:raise UserError('群超出当前账号授权范围')
            proof=json.loads((self.data/'requested-contact-cache.json').read_text(encoding='utf-8'))
            if (proof['pid']!=session['pid'] or proof['process_created']!=session['created']
                    or Path(proof['account_root'])!=self.account_root):raise UserError('联系人缓存属于旧会话')
            matches=[r for r in proof['records'] if r['name']==group and r['is_in_chat_room']]
            if len(matches)<2 or {r['room_id'] for r in matches}!={requested[group]}:
                raise UserError('指定群名与本机联系人记录不一致')
            self.room=requested[group];self.name=group;self.aliases={group}
            self.table='Msg_'+hashlib.md5(self.room.encode()).hexdigest()

    def binding(self):
        return {**super().binding(), 'group_name_source': 'user_confirmed_test_message',
                'account_binding_source': 'authenticated_self_message',
                'contact_name_verified': False}
