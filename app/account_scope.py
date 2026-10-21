"""Authenticated conversation discovery for the explicitly authorized account."""
import hashlib,json,re,time
from pathlib import Path
from history_reader import HistoryView,SnapshotChanged
from session_history import SessionHistory
from lab import UserError

def stable_read(operation, attempts=4):
    for attempt in range(attempts):
        try:
            return operation()
        except SnapshotChanged:
            if attempt == attempts - 1:
                raise
            time.sleep(.1 * (attempt + 1))

SYSTEM_PEERS={'filehelper','weixin','fmessage','tmessage','qqmail','newsapp','medianote','floatbottle','qmessage','masssendapp','mphelper','notifymessage'}

def peer_kind(peer):
    if re.fullmatch(r'\d{5,20}@chatroom',peer or ''):return 'group'
    if (not isinstance(peer,str) or peer in SYSTEM_PEERS or peer.startswith(('gh_','weixin','openim'))
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',peer)):return None
    return 'direct'

def load_scope(data):
    data=Path(data)
    scope=json.loads((data/'reply-scope.json').read_text(encoding='utf-8'))
    session=json.loads((data/'session.json').read_text(encoding='utf-8'))
    if (scope.get('pid')!=session['pid'] or scope.get('process_created')!=session['created']
            or scope.get('account_root')!=session['account_roots'][0]):raise UserError('自动回复范围属于旧账号会话')
    return scope

def validate_recipient(data,peer):
    data=Path(data);scope=load_scope(data);kind=peer_kind(peer)
    if not kind or not scope.get('all_groups_mentions' if kind=='group' else 'all_direct_messages'):
        raise UserError('会话不在当前授权范围')
    registry=json.loads((data/'peer-registry.json').read_text(encoding='utf-8'))
    if registry.get('account_root')!=scope['account_root']:raise UserError('会话登记属于其他账号')
    entry=registry['peers'].get(peer)
    if not entry or entry.get('authenticated_table')!='Msg_'+hashlib.md5(peer.encode()).hexdigest():
        raise UserError('接收人未通过本机消息表认证')
    return entry

def discover(base,data):
    return stable_read(lambda: _discover_once(base,data))

def _discover_once(base,data):
    data=Path(data);scope=load_scope(data)
    names={g['room_id']:g['configured_name'] for g in json.loads((data/'monitored-groups.json').read_text(encoding='utf-8'))}
    found={}
    for path in base.message_paths():
        key,salt=base.keys[path]
        with HistoryView(path,key,salt) as view:
            tables={r[0] for r in view.query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")}
            peers=[r[0] for r in view.query('SELECT user_name FROM Name2Id')]
            for peer in peers:
                kind=peer_kind(peer)
                if not kind or peer==base.account:continue
                table='Msg_'+hashlib.md5(peer.encode()).hexdigest()
                if table not in tables:continue
                if not scope.get('all_groups_mentions' if kind=='group' else 'all_direct_messages'):continue
                latest=view.query('SELECT COALESCE(MAX(create_time),0) FROM "'+table+'"')[0][0]
                found[peer]={'peer':peer,'kind':kind,'configured_name':names.get(peer,'会话-'+hashlib.md5(peer.encode()).hexdigest()[:16]),
                             'name':names.get(peer,'其他群聊' if kind=='group' else '私聊'),
                             'group_model_authorized':True,'authenticated_table':table,'registered_since':scope['activated_at'],
                             'last_message_time':max(latest,found.get(peer,{}).get('last_message_time',0)),'previously_enabled':peer in names}
    path=data/'peer-registry.json';tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps({'account_root':scope['account_root'],'peers':found},ensure_ascii=False,indent=2),encoding='utf-8');tmp.replace(path)
    return found

class AccountHistory(SessionHistory):
    def __init__(self,base,entry):
        self.__dict__=dict(base.__dict__)
        validate_recipient(self.data,entry['peer'])
        self.entry=entry;self.room=entry['peer'];self.table=entry['authenticated_table']
        self.name=entry['configured_name'];self.aliases={self.name}
    def binding(self):
        return {**super().binding(),'kind':self.entry['kind'],'binding_source':'authenticated_message_table'}
