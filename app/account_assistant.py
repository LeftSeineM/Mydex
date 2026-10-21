"""Authorized account conversations, restricted by the current reply scope."""
import hashlib,json,msvcrt,threading,time,sys
from pathlib import Path
import psutil
from lab import Settings,Store,Engine,Backend,UserError
from group_scopes import GroupSettings
from m_session_assistant import DATA,save,check_session
from session_history import SessionHistory
from account_scope import discover,load_scope,AccountHistory,validate_recipient,stable_read,SnapshotChanged
from conversation_queue import ConversationInbox,LimitedBackend
from native_sender_bridge import NativeSender
from desktop_operator import DesktopBridge
from group_participation import ParticipationSettings,load_policy
from reply_hours import replies_allowed
import conversation_queue

class AccountInbox(ConversationInbox):
    def __init__(self,*args,entry,desktop_bridge=None,receiving_account=None,**kwargs):
        self.entry=entry
        self.desktop_bridge=desktop_bridge;self.receiving_account=receiving_account
        self.accept_since=entry.get('runtime_started', time.time())
        super().__init__(*args,**kwargs)
        if entry['kind']=='group' and self.cursors:
            # Resume unread recent messages from a saved cursor across restarts.
            self.accept_since=max(entry['registered_since'],self.accept_since-600)
        with self.engine.store.lock,self.engine.store.db:
            self.engine.store.db.execute("UPDATE model_jobs SET state='expired' WHERE room=? AND state IN ('pending','model_running')", (self.room,))
        if not self.checkpoint.exists():
            reader=self.reader_factory()
            self.cursors={p:0 for p in reader.message_paths()}
    def consider_event(self,event):
        if event.get('created',0)<max(self.accept_since,self.entry['registered_since']):return
        if not replies_allowed():return
        if self.engine.settings.get().get('replies_paused'):return
        if self.entry['kind']=='direct':
            if not load_scope(DATA).get('all_direct_messages',False):return
            if (not event.get('is_self') and event.get('sender')==self.entry['peer']
                    and event.get('type')!='system'):
                if self.desktop_bridge and self.desktop_bridge.capture(event,self.entry,self.receiving_account):return
                self.enqueue({**event,'direct_verified':True})
            return
        super().consider_event(event)

    def consider_baseline_event(self,event):
        event_id=str(event.get('id',''))
        if (self.entry['kind']=='group' and event.get('type') in ('text','quote')
                and event.get('mention_verified') is True and not event.get('is_self')
                and event_id.isdecimal() and int(event_id)>0):
            self.consider_event(event)

    def cycle(self,reader):
        super().cycle(reader)
        if self.desktop_bridge and not self.stop_event.is_set():
            self.desktop_bridge.deliver_one(self.entry,self.receiving_account,self.sender)

class AccountSender(NativeSender):
    def __init__(self,engine,session,base,registry):
        self.session=session;self.base=base;self.registry=registry
        super().__init__(engine,data=DATA)
    def verify_session(self):
        super().verify_session();check_session(self.session)
    def send_window_open(self):
        return replies_allowed()
    def allowed_targets(self):
        direct_enabled=load_scope(DATA).get('all_direct_messages',False)
        return {entry['configured_name']:peer for peer,entry in self.registry.copy().items()
                if entry['kind']=='group' or direct_enabled}
    def display_name(self,room):
        entry=next((item for item in self.registry.copy().values()
                    if item['configured_name']==room),None)
        if entry is None:raise UserError('会话未登记')
        from group_participation import HACKATHON_ROOM
        if entry['peer']==HACKATHON_ROOM and entry['kind']=='group':
            return 'EE黑客松·官方小bot'
        return super().display_name(room)
    def reader(self,group=None):
        entry=next((v for v in self.registry.copy().values() if v['configured_name']==group),None)
        if entry is None:raise UserError('会话未登记')
        validate_recipient(DATA,entry['peer'])
        return AccountHistory(self.base,entry)

def main():
    lock=open(DATA/'assistant.lock','a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:return
    inboxes={};sender=None;model_threads=[]
    def report(phase,**extra):
        save('assistant-status.json',{'phase':phase,'runner_pid':psutil.Process().pid,'at':time.time(),
             'runtime':'account_assistant','mode':'group_mentions_only' if not load_scope(DATA).get('all_direct_messages',False) else 'all_group_mentions_and_private_messages',**extra})
    try:
        session=json.loads((DATA/'session.json').read_text(encoding='utf-8'));check_session(session)
        scope=load_scope(DATA);base=stable_read(lambda:SessionHistory(DATA));settings=Settings()
        store=Store(DATA/'history.sqlite3');backend=LimitedBackend(Backend());desktop_bridge=DesktopBridge(DATA)
        participation=load_policy(DATA)
        desktop_bridge.start_run()
        desktop_operator_enabled=bool(desktop_bridge.config() and desktop_bridge.config().get('enabled'))
        if desktop_operator_enabled:conversation_queue.MODEL_SLOTS=threading.BoundedSemaphore(3)
        registry=discover(base,DATA)
        from member_labels import refresh_account_labels
        refresh_account_labels(base,registry,DATA)
        main_engine=Engine(settings,store,backend=backend,data=DATA)
        sender=AccountSender(main_engine,session,base,registry)
        if not sender.state(fresh=True)['connected']:raise UserError('发送组件未连接')
        checked=time.monotonic();labels_checked=checked;runtime_started=time.time();discovery_deferred=False
        while not (DATA/'stop.request').exists():
            check_session(session)
            if time.monotonic()-checked>=3:
                checked=time.monotonic()
                try:
                    base.refresh_keys()
                    refreshed=discover(base,DATA)
                except SnapshotChanged:
                    discovery_deferred=True
                else:
                    registry.update(refreshed)
                    if time.monotonic()-labels_checked>=60:
                        refresh_account_labels(base,registry,DATA)
                        labels_checked=time.monotonic()
                    discovery_deferred=False
            for peer,entry in list(registry.items()):
                if peer in inboxes or (not entry['previously_enabled'] and entry['last_message_time']<scope['activated_at']):continue
                reader=AccountHistory(base,entry)
                engine=Engine(ParticipationSettings(settings,entry,participation),store,backend=backend,data=DATA)
                inbox=AccountInbox(engine,data=DATA,reader_factory=lambda r=reader:r,sender=sender,scope=peer,entry={**entry,'runtime_started':runtime_started},desktop_bridge=desktop_bridge,receiving_account=base.account)
                inbox.start();inboxes[peer]=inbox
            report('running',account='M',model=settings.get()['model'],model_concurrency_limit=4,
                   qwen_concurrency_limit=3 if desktop_operator_enabled else 4,desktop_operator=desktop_operator_enabled,
                   queue_capacity_per_conversation=100,all_groups_mentions=scope['all_groups_mentions'],all_direct_messages=load_scope(DATA).get('all_direct_messages',False),
                   ordinary_group_participation=participation['enabled'],minimum_ordinary_messages=participation['minimum_ordinary_messages'],
                   always_reply_rooms=participation.get('always_reply_rooms',[]),
                   discovered_conversations=len(registry),sender=sender.state(),discovery_deferred=discovery_deferred,
                   groups=[{'name':i.entry['name'],'kind':i.entry['kind'],**i.state()} for i in inboxes.values()])
            time.sleep(1)
        report('stopping')
    except Exception as exc:
        report('needs_attention',error=str(exc) if isinstance(exc,UserError) else type(exc).__name__)
        return 75 if isinstance(exc,SnapshotChanged) else 0
    finally:
        if sender:sender.enabled=False
        for item in inboxes.values():item.stop()
        for item in inboxes.values():
            if item.thread:item.thread.join(timeout=3)
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()

if __name__=='__main__':sys.exit(main())
