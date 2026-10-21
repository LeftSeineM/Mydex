"""Run Mydex for the explicitly verified M account and work-base group only.

Uses an isolated message store and the previously validated native text sender.
Never installs hooks, adopts guessed threads, or retries an uncertain send.
"""
import json
import msvcrt
from pathlib import Path
import time
import psutil
from lab import ROOT, Settings, Store, Engine, UserError, Backend
from database_inbox import DatabaseInbox
from native_sender_bridge import NativeSender
from session_history import SessionHistory
from conversation_queue import ConversationInbox,LimitedBackend
from group_scopes import GroupSettings
from research.inspect_open_databases import inventory

DATA = ROOT/'.local/quote-m-session'
ANNOUNCEMENT = ('Mydex：\n我是群研究助手Mydex，已上线。\n\n'
                '当前模型：Qwen3.8-Flash。用微信成员选择功能 @M 提问，我会在本群回答。\n'
                '支持：常识问答、写作与编程、群聊总结、待办整理。\n'
                '群聊历史以本机已同步记录为准；当前未接入联网搜索。')

def save(name, value):
    path=DATA/name; temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    temporary.replace(path)

def action(pid, command, body='', room=None, data=DATA):
    path=DATA/'native-sender-settings.json'
    config=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    if config.get('sender_version')==5:
        from research.worker_sender_v5.run import action as execute
    else:
        from research.worker_sender_v4.run import action as execute
    return execute(pid,command,body,room=room,data=data)

def check_session(session):
    proc=psutil.Process(session['pid'])
    if proc.create_time()!=session['created']:
        raise UserError('微信进程已更换，需要重新绑定')
    paths=inventory(proc.pid)['database_paths']
    roots={str(Path(p).parents[2]) for p in paths if 'db_storage' in Path(p).parts and Path(p).suffix=='.db'}
    if roots!=set(session['account_roots']):
        raise UserError('当前登录账号发生变化，M 的监听已停止')

class BoundSender(NativeSender):
    def __init__(self, engine, session, reader):
        self.session=session
        super().__init__(engine,data=DATA,reader_factory=lambda:reader)
    def verify_session(self):
        super().verify_session()
        check_session(self.session)
    def reader(self,group=None):
        return SessionHistory(DATA,group=group)

def matches(reader, body, since, cursors):
    for path,cursor in cursors.items():
        for event in reader.fetch(path,reader.name,cursor)['events']:
            if (event['is_self'] and event['content']==body
                    and event['id'].isdigit() and int(event['id'])):
                return event
    return None

def bootstrap(session, reader):
    """Send one requested online notice, proving this account's return path."""
    proof_path=DATA/'native-delivery-proof.json'
    if proof_path.exists():
        proof=json.loads(proof_path.read_text(encoding='utf-8'))
        if proof.get('pid')==session['pid'] and proof.get('process_created')==session['created'] and proof.get('server_record_verified'):
            return proof
    intent_path=DATA/'online-notice-intent.json'
    if intent_path.exists():
        intent=json.loads(intent_path.read_text(encoding='utf-8'))
        if intent['pid']!=session['pid'] or intent['process_created']!=session['created']:
            raise UserError('上线通知属于旧进程，需核对后重新绑定')
    else:
        intent={'pid':session['pid'],'process_created':session['created'],'at':time.time(),
                'body':ANNOUNCEMENT,'cursors':{p:reader.latest_cursor(p,reader.name) for p in reader.message_paths()}}
        check_session(session)
        save('online-notice-intent.json',intent)
        queued=action(session['pid'],'send',intent['body'],room=reader.room,data=DATA)
        if queued.get('return_code')!=0:
            raise UserError('上线通知未成功入队，保留现场，不自动重发')
    deadline=time.monotonic()+35
    while time.monotonic()<deadline:
        check_session(session)
        event=matches(reader,intent['body'],intent['at'],intent['cursors'])
        if event:
            proof={'pid':session['pid'],'process_created':session['created'],
                   'server_record_verified':True,'native_delivery_verified':True,
                   'matches':[{'room_id':reader.room,'server_id':event['id']}],
                   'account_id':reader.account,'at':time.time()}
            save('native-delivery-proof.json',proof)
            return proof
        time.sleep(.5)
    raise UserError('上线通知回执尚未验证；不自动重发，请核对群中是否收到')

def main():
    lock=open(DATA/'assistant.lock','a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:return
    inbox=None;sender=None;store=None;inboxes=[]
    def status(phase,**extra):
        save('assistant-status.json',{'phase':phase,'runner_pid':psutil.Process().pid,'at':time.time(),**extra})
    try:
        session=json.loads((DATA/'session.json').read_text(encoding='utf-8'))
        check_session(session)
        reader=SessionHistory(DATA)
        while True:
            if (DATA/'stop.request').exists():return
            check_session(session)
            native=action(session['pid'],'status',data=DATA)
            if native.get('phase')!=2:raise UserError('原生发送组件未就绪')
            if native.get('worker_thread'):break
            status('waiting_for_desktop_message',group=reader.name,account='M')
            time.sleep(2)
        proof=bootstrap(session,reader)
        previous=json.loads((DATA/'native-sender-settings.json').read_text(encoding='utf-8')) if (DATA/'native-sender-settings.json').exists() else {}
        save('native-sender-settings.json',{**previous,'pid':session['pid'],'process_created':session['created'],
             'enabled':True,'account_verified':True,'group_id':reader.room})
        save('member-labels.json',{'groups':[{'aliases':sorted(reader.aliases),'labels':{reader.account:'M'}}]})
        policy=ROOT/'.local/send-policy.json'
        if policy.exists():save('send-policy.json',json.loads(policy.read_text(encoding='utf-8')))
        settings=Settings()
        if settings.get()['group'] not in reader.aliases:raise UserError('模型配置群与本次绑定不一致')
        store=Store(DATA/'history.sqlite3')
        backend=LimitedBackend(Backend())
        engine=Engine(settings,store,backend=backend,data=DATA)
        sender=BoundSender(engine,session,reader)
        if not sender.state(fresh=True)['connected']:raise UserError('发送线程连接未确认')
        entries=json.loads((DATA/'monitored-groups.json').read_text(encoding='utf-8'))
        for entry in entries:
            bound=SessionHistory(DATA,group=entry['configured_name'])
            group_engine=Engine(GroupSettings(settings,entry),store,backend=backend,data=DATA)
            group_inbox=ConversationInbox(group_engine,data=DATA,reader_factory=lambda r=bound:r,sender=sender,scope=entry['room_id'])
            group_inbox.start();inboxes.append(group_inbox)
        inbox=inboxes[0]
        while not (DATA/'stop.request').exists():
            check_session(session)
            current=inbox.state()
            status('running',group=reader.name,account='M',model=settings.get()['model'],
                   online_notice_verified=True,inbox=current,sender=sender.state(),
                   groups=[{'name':i.engine.settings.get()['group'],**i.state()} for i in inboxes],
                   model_concurrency_limit=4,queue_capacity_per_group=100)
            time.sleep(2)
        status('stopped')
    except Exception as exc:
        status('needs_attention',error=str(exc) if isinstance(exc,UserError) else type(exc).__name__)
    finally:
        if sender:sender.enabled=False
        for item in inboxes:item.stop()
        for item in inboxes:
            if item.thread:item.thread.join(timeout=5)
        # A pending model call may still hold the store; do not close it early.
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()

if __name__=='__main__':main()
