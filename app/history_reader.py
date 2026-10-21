"""Read only the sample-bound group's authenticated local databases.

Keys stay in RAM after CurrentUser DPAPI; app XML is reduced to useful fields.
The immutable SQLite view authenticates pages and never writes source files.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import xml.etree.ElementTree as ET

from lab import DATA, ROOT, UserError
sys.path.insert(0, str(ROOT / 'research'))
from history_crypto import dpapi
from history_vfs import HistoryView, SnapshotChanged, identity
from read_target_history import text_value
from native_inbox import verified_mention
from public_web_reader import extract_public_urls, normalize_public_url


def _app_public_url(app):
    for path in ('url', './/webviewshared/url'):
        value = normalize_public_url(app.findtext(path, '') or '')
        if value:
            return value
    return None


def app_fields(body, _depth=0):
    if not isinstance(body, str) or len(body) > 1048576 or '<!DOCTYPE' in body.upper():
        raise ValueError('Invalid app message')
    root = ET.fromstring(body)
    app = root if root.tag == 'appmsg' else root.find('.//appmsg')
    if app is None:
        return {'kind': 'unsupported'}
    kind = app.findtext('type', '')
    title = (app.findtext('title', '') or '')[:2000]
    if kind == '6':
        attachment = app.find('appattach')
        size = attachment.findtext('totallen', '') if attachment is not None else ''
        digest = ''
        if attachment is not None:
            digest = attachment.findtext('filemd5', '') or attachment.findtext('md5', '')
        digest = digest or app.findtext('md5', '') or app.findtext('filemd5', '')
        # CDN URLs, AES keys, upload tokens and arbitrary XML never enter context.
        return {'kind': 'attachment', 'title': title,
                'size': int(size) if size.isdecimal() and len(size) <= 12 else None,
                'md5': digest.lower() if re.fullmatch('[0-9a-fA-F]{32}', digest or '') else None,
                'extension': (attachment.findtext('fileext', '') if attachment is not None else '')[:20]}
    if kind == '57':
        reference = app.find('refermsg')
        quoted = reference.findtext('content', '') if reference is not None else ''
        nested = None
        # A referenced app message can contain another credential-bearing XML.
        if quoted.lstrip().startswith('<'):
            if _depth == 0:
                try:
                    nested = app_fields(quoted, _depth=1)
                except (ValueError, ET.ParseError):
                    pass
            if nested and nested.get('kind') == 'link':
                quoted = '【引用网页】' + nested.get('title', '') + '\n' + nested['url']
            else:
                quoted = '【引用的非文字消息】'
        result = {'kind': 'quote', 'title': title, 'quoted': quoted[:2000],
                  'quoted_sender': (reference.findtext('displayname', '') if reference is not None else '')[:128]}
        result['public_urls'] = extract_public_urls([_app_public_url(app), *extract_public_urls(quoted)], limit=2)
        if nested and nested.get('public_urls'):
            result['public_urls'] = list(dict.fromkeys(result['public_urls'] + nested['public_urls']))[:2]
        return result
    public_url = _app_public_url(app)
    if public_url:
        return {'kind': 'link', 'app_type': kind[:20], 'title': title,
                'url': public_url, 'public_urls': [public_url]}
    return {'kind': 'app', 'app_type': kind[:20], 'title': title}


def normalize_row(row, room, group, account, filename):
    local_id, server_id, kind, created, sender, content, compressed, source, sort_seq = row
    event_id = str(server_id) if server_id else filename + ':' + str(local_id)
    if not sender:
        sender = '系统'
    body = text_value(content) or text_value(compressed)
    if body.startswith(sender + ':\n'):
        body = body[len(sender) + 2:]
    native_type = kind & 0xffffffff
    details = None
    message_type = 'text'
    if native_type == 49:
        details = app_fields(body)
        if details['kind'] == 'attachment':
            message_type = 'attachment'
            body = '【群文件】' + details['title'] + '\n'
            if details['size'] is not None:
                body += '文件大小：' + str(details['size']) + ' 字节。'
            body += '文件正文尚未读取。'
        elif details['kind'] == 'quote':
            message_type = 'quote'
            body = details['title'] + '\n【引用 ' + details['quoted_sender'] + '】' + details['quoted']
        elif details['kind'] == 'link':
            message_type = 'link'
            body = '【网页】' + details.get('title', '') + '\n' + details['url']
        else:
            message_type = 'media'
            body = '【应用消息 ' + details.get('app_type', '') + '】' + details.get('title', '') + '（正文未解析）'
    elif native_type != 1:
        message_type = 'system' if native_type in (10000, 10002) else 'media'
        label = {3: '图片', 34: '语音', 43: '视频', 47: '表情', 10000: '系统', 10002: '系统'}.get(native_type, '非文字')
        # Do not import nested media XML or a revoked original message.
        body = '【' + label + '消息：正文尚未解析】'
    if not body:
        raise ValueError('Empty text message')
    if len(body) > 8000:
        body = body[:7800] + '【该条消息超过长度限制，已截断】'
    try:
        msg_source = text_value(source)
    except (ValueError, UnicodeError):
        msg_source = ''
    event = {'source': 'wechat', 'room': group, 'room_id': room,
             'sender': sender, 'content': body, 'id': event_id, 'created': created,
             'type': message_type, 'is_self': sender == account,
             'mention_verified': verified_mention(msg_source, account),
             'local_id': local_id, 'sort_seq': sort_seq or 0, 'database': filename}
    if details is not None and details['kind'] == 'attachment':
        event['attachment'] = details
    if details is not None and details.get('public_urls'):
        event['public_urls'] = details['public_urls']
    return event


class TargetHistory:
    def __init__(self, data=DATA, group=None):
        self.data = Path(data)
        evidence = json.loads((self.data / 'outbound-sample-evidence.json').read_text(encoding='utf-8-sig'))
        self.room = evidence['room_id_candidate']
        if not re.fullmatch(r'\d+@chatroom', self.room):
            raise UserError('群标识格式不正确')
        self.table = 'Msg_' + hashlib.md5(self.room.encode()).hexdigest()
        profile = json.loads((self.data / 'history-file-profile.json').read_text(encoding='utf-8'))
        self.allowed = {str(Path(r['parent']) / r['name']) for r in profile
                        if r['name'] in ('contact.db', 'message_0.db', 'message_1.db', 'message_2.db', 'message_3.db')}
        parents = {Path(p).parent.parent.parent for p in self.allowed}
        if len(parents) != 1:
            raise UserError('数据库账号目录不一致')
        self.account_root = parents.pop()
        match = re.fullmatch(r'(wxid_[A-Za-z0-9]+)_[0-9a-fA-F]{4}', self.account_root.name)
        if not match:
            raise UserError('当前本机账号标识无法确认')
        self.account = match.group(1)
        schema = json.loads((self.data / 'history-schema.json').read_text(encoding='utf-8'))
        actual = [r.get('nick_name') for f in schema['files'] for r in f.get('target_contact', []) if r.get('username') == self.room]
        if len(set(actual)) != 1 or not actual[0]:
            raise UserError('群名未通过本机联系人记录核对')
        self.name = actual[0]
        self.aliases = {self.name, evidence['group_name']}
        self.keys = {}
        self.refresh_keys()
        self.history_since = 0
        if group is not None and group not in self.aliases:
            scopes=json.loads((self.data/'monitored-groups.json').read_text(encoding='utf-8'))
            entry=next((g for g in scopes if group in (g['name'],g['configured_name'])),None)
            if not entry or not re.fullmatch(r'\d+@chatroom',entry['room_id']):
                raise UserError('群未加入明确的监听范围')
            contacts=[p for p in self.keys if Path(p).name=='contact.db']
            if len(contacts)!=1:raise UserError('联系人数据库未认证')
            key,salt=self.keys[contacts[0]]
            with HistoryView(contacts[0],key,salt) as view:
                rows=view.query('SELECT nick_name FROM contact WHERE username=?',(entry['room_id'],))
            if rows!=[(entry['name'],)]:raise UserError('新增群名与联系人记录不一致')
            self.room=entry['room_id'];self.name=entry['name']
            self.aliases={self.name,entry['configured_name']}
            self.table='Msg_'+hashlib.md5(self.room.encode()).hexdigest()
            if not entry.get('history_import'):
                self.history_since=entry.get('added_at',(self.data/'monitored-groups.json').stat().st_mtime)

    def refresh_keys(self):
        # This file contains only DPAPI ciphertext; never log its decoded value.
        private = json.loads(dpapi((self.data / 'history-keys.dpapi').read_bytes(), True))
        for item in private['files']:
            if item['path'] not in self.allowed:
                continue
            key, salt = bytes.fromhex(item['key']), bytes.fromhex(item['salt'])
            if len(key) != 32 or len(salt) != 16:
                raise UserError('数据库解密材料格式不正确')
            self.keys[item['path']] = (key, salt)
        return self.message_paths()

    def message_paths(self):
        return sorted(p for p in self.keys if re.fullmatch(r'message_\d+\.db', Path(p).name))

    def fingerprint(self, path):
        return identity(path), identity(str(path) + '-wal')

    def latest_cursor(self, path, group):
        """Get a send-verification baseline without loading message bodies."""
        if group not in self.aliases or path not in self.message_paths():
            raise UserError('读取范围与绑定群不一致')
        key, salt = self.keys[path]
        for attempt in range(3):
            try:
                with HistoryView(path, key, salt) as view:
                    if not view.query('SELECT name FROM sqlite_master WHERE type=? AND name=?', ('table', self.table)):
                        return 0
                    return view.query('SELECT COALESCE(MAX(local_id),0) FROM "' + self.table + '"')[0][0]
            except SnapshotChanged:
                if attempt == 2:
                    raise
                time.sleep(.08)

    def fetch(self, path, group, after=None):
        if group not in self.aliases or path not in self.message_paths():
            raise UserError('读取范围与绑定群不一致')
        key, salt = self.keys[path]
        for attempt in range(3):
            try:
                with HistoryView(path, key, salt) as view:
                    if not view.query('SELECT name FROM sqlite_master WHERE type=? AND name=?', ('table', self.table)):
                        return {'events': [], 'cursor': 0, 'stored_rows': 0, 'read_rows': 0, 'rejected': 0, 'target_table': False}
                    count, highest = view.query('SELECT COUNT(*),COALESCE(MAX(local_id),0) FROM "' + self.table + '"')[0]
                    fields = ('SELECT m.local_id,m.server_id,m.local_type,m.create_time,n.user_name,'
                              'm.message_content,m.compress_content,m.source,m.sort_seq '
                              'FROM "' + self.table + '" AS m LEFT JOIN Name2Id AS n ON n.rowid=m.real_sender_id ')
                    if after is None:
                        rows = view.query(fields + ('WHERE m.create_time>=? ' if self.history_since else '') +
                                          'ORDER BY m.local_id DESC LIMIT 50000', (int(self.history_since),) if self.history_since else ())
                        rows.reverse()
                    else:
                        rows = view.query(fields + 'WHERE m.local_id>? ORDER BY m.local_id ASC LIMIT 1000', (after,))
                    events = []
                    rejected = 0
                    for row in rows:
                        try:
                            events.append(normalize_row(row, self.room, group, self.account, Path(path).name))
                        except (ValueError, UnicodeError, ET.ParseError):
                            rejected += 1
                    cursor = (rows[-1][0] if rows else after) if after is not None else highest
                    return {'events': events, 'cursor': cursor, 'stored_rows': count, 'read_rows': len(rows),
                            'rejected': rejected, 'target_table': True, 'pages_read': view.snapshot.pages_read}
            except SnapshotChanged:
                if attempt == 2:
                    raise
                time.sleep(.08)

    def binding(self):
        return {'group_name': self.name, 'configured_aliases': sorted(self.aliases),
                'room_id': self.room, 'account_id': self.account,
                'group_name_verified': True, 'authenticated_message_shards': len(self.message_paths()),
                'history_completeness': 'unknown'}
