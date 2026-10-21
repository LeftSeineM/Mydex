"""Durable per-group FIFO with bounded shared model concurrency.

Conversation choices are local policy. Never fabricate a WeChat @ marker.
Failed model calls may retry; an uncertain native delivery never auto-retries.
"""
import json,re,threading,time
from database_inbox import DatabaseInbox
from lab import UserError

MODEL_SLOTS=threading.BoundedSemaphore(4)

class LimitedBackend:
    def __init__(self,backend):self.backend=backend
    def reply(self,cfg,messages):
        with MODEL_SLOTS:return self.backend.reply(cfg,messages)

def is_question(text):
    text=text.strip()
    return bool(re.search(r'[?？]|怎么|为什么|为何|什么|哪[个里种]|谁|多少|能不能|可不可以|是否|请问|帮我|帮忙|求推荐|求助|总结|分析一下|解释一下|[吗么嘛](?:[。！!\s]|$)',text))

def visible_mention(text, aliases):
    if not isinstance(text,str) or not isinstance(aliases,list):return False
    return any(re.search(r'(^|\s)@'+re.escape(alias)+r'(?=$|\s|[，,:：。!?！？])',text)
               for alias in aliases)

class ConversationInbox(DatabaseInbox):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.room=self.engine.settings.get()['group']
        self.last_chat=0
        with self.engine.store.lock,self.engine.store.db:
            self.engine.store.db.execute('''CREATE TABLE IF NOT EXISTS model_jobs(
                room TEXT NOT NULL,event_id TEXT NOT NULL,event TEXT NOT NULL,state TEXT NOT NULL,
                ready REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(room,event_id))''')
            self.engine.store.db.execute("UPDATE model_jobs SET state='pending' WHERE room=? AND state='model_running'",(self.room,))
            # Delivery may already have happened: do not retry that state.
            self.engine.store.db.execute("UPDATE model_jobs SET state='needs_review' WHERE room=? AND state='sending'",(self.room,))
            self.engine.store.db.execute('''CREATE TABLE IF NOT EXISTS participation_counts(
                room TEXT PRIMARY KEY,observed INTEGER NOT NULL DEFAULT 0,reserved INTEGER NOT NULL DEFAULT 0)''')
            self.engine.store.db.execute('''CREATE TABLE IF NOT EXISTS participation_events(
                room TEXT NOT NULL,event_id TEXT NOT NULL,PRIMARY KEY(room,event_id))''')
        self.checkpoint=self.output.with_name(self.output.stem+'-cursor.json')
        if self.checkpoint.exists():
            value=json.loads(self.checkpoint.read_text(encoding='utf-8'))
            if value.get('room')==self.room:self.cursors=value.get('cursors',{})

    def consider_event(self,event):
        if event.get('type') not in ('text','quote'):return
        cfg=self.engine.settings.get()
        if (not event.get('is_self') and not event.get('mention_verified')
                and visible_mention(event.get('content',''),cfg.get('visible_mention_aliases',[]))):
            event={**event,'visible_mention_authorized':True}
        explicit=event.get('self_command_verified') or (event.get('mention_verified') and not event.get('is_self'))
        explicit=explicit or event.get('visible_mention_authorized') is True
        if explicit:self.enqueue(event);return
        if event.get('is_self') or not cfg.get('conversation_enabled'):return
        if cfg.get('conversation_reply_all'):
            if event.get('type','text') not in ('text','quote') or not event.get('content','').strip():return
            self.enqueue({**event,'conversation_verified':True,'conversation_reason':'always_reply'})
            return
        minimum=cfg.get('conversation_min_messages',0)
        if minimum and not self.observe_ordinary(event,minimum):return
        text=event['content'].strip()
        question=is_question(text)
        # An occasional substantive conversational contribution, never emoji echoes.
        casual=(len(text)>=25 and time.time()-self.last_chat>=300 and not text.startswith(('Mydex','【')))
        if not question and not casual:return
        tagged={**event,'conversation_verified':True,'conversation_reason':'question' if question else 'occasional_chat'}
        if self.enqueue(tagged) and casual and not question:self.last_chat=time.time()

    def observe_ordinary(self,event,minimum):
        if (event.get('source')!='wechat' or event.get('room')!=self.room
                or not event.get('id') or not -5<=time.time()-event.get('created',0)<=600):return False
        store=self.engine.store
        with store.lock,store.db:
            added=store.db.execute('INSERT OR IGNORE INTO participation_events(room,event_id) VALUES(?,?)',
                                   (self.room,str(event['id']))).rowcount
            if not added:return False
            store.db.execute('INSERT OR IGNORE INTO participation_counts(room) VALUES(?)',(self.room,))
            store.db.execute('UPDATE participation_counts SET observed=observed+1 WHERE room=?',(self.room,))
            row=store.db.execute('SELECT observed,reserved FROM participation_counts WHERE room=?',(self.room,)).fetchone()
            return row['observed']-row['reserved']>=minimum

    def enqueue(self,event):
        now=time.time()
        if not -5<=now-event.get('created',0)<=600:return False
        if event.get('source')!='wechat' or event.get('room')!=self.room:return False
        if not (event.get('self_command_verified') or (not event.get('is_self') and
                (event.get('mention_verified') or event.get('visible_mention_authorized')
                 or event.get('conversation_verified') or event.get('direct_verified')))):return False
        store=self.engine.store
        with store.lock,store.db:
            if store.db.execute('SELECT 1 FROM model_jobs WHERE room=? AND event_id=?',(self.room,event['id'])).fetchone():return False
            count=store.db.execute("SELECT COUNT(*) FROM model_jobs WHERE room=? AND state IN ('pending','model_running','sending')",(self.room,)).fetchone()[0]
            if count>=100:
                self.report(last_skip_reason='queue_full_history_retained');return False
            minimum=self.engine.settings.get().get('conversation_min_messages',0)
            limited=bool(minimum and event.get('conversation_verified'))
            if limited:
                row=store.db.execute('SELECT observed,reserved FROM participation_counts WHERE room=?',(self.room,)).fetchone()
                observed=store.db.execute('SELECT 1 FROM participation_events WHERE room=? AND event_id=?',
                                         (self.room,str(event['id']))).fetchone()
                active=store.db.execute("SELECT event FROM model_jobs WHERE room=? AND state IN ('pending','model_running','sending')",(self.room,)).fetchall()
                if (not row or not observed or row['observed']-row['reserved']<minimum
                        or any(json.loads(job['event']).get('conversation_verified') for job in active)):return False
            # Merge nearby ordinary questions from the same person; explicit @ stays independent.
            if event.get('conversation_verified') and event.get('conversation_reason')!='always_reply':
                rows=store.db.execute("SELECT event_id,event FROM model_jobs WHERE room=? AND state='pending' AND ready>?",(self.room,now)).fetchall()
                for row in rows:
                    previous=json.loads(row['event'])
                    if previous['sender']==event['sender'] and previous.get('conversation_verified') and now-previous['created']<10:
                        store.db.execute("UPDATE model_jobs SET state='merged' WHERE room=? AND event_id=?",(self.room,row['event_id']))
            store.db.execute('INSERT INTO model_jobs(room,event_id,event,state,ready) VALUES(?,?,?,?,?)',
                (self.room,event['id'],json.dumps(event,ensure_ascii=False),'pending',now+(2 if event.get('conversation_verified') else 0)))
            if limited:store.db.execute('UPDATE participation_counts SET reserved=observed WHERE room=?',(self.room,))
        return True

    def cycle(self,reader):
        super().cycle(reader)
        temporary=self.checkpoint.with_suffix('.tmp')
        temporary.write_text(json.dumps({'room':self.room,'cursors':self.cursors}),encoding='utf-8');temporary.replace(self.checkpoint)

    def set_job(self,event_id,state,error=''):
        with self.engine.store.lock,self.engine.store.db:
            self.engine.store.db.execute('UPDATE model_jobs SET state=?,error=? WHERE room=? AND event_id=?',(state,error,self.room,event_id))
            if state=='sent' and self.engine.settings.get().get('conversation_min_messages'):
                job=self.engine.store.db.execute('SELECT event FROM model_jobs WHERE room=? AND event_id=?',(self.room,event_id)).fetchone()
                if job and json.loads(job['event']).get('conversation_verified'):
                    # Require ten NEW ordinary messages after actual delivery,
                    # even if many messages arrived while the model was working.
                    self.engine.store.db.execute('UPDATE participation_counts SET reserved=observed WHERE room=?',(self.room,))

    def summarize(self):
        store=self.engine.store
        while not self.stop_event.is_set():
            if not self.engine.settings.get().get('group_model_authorized'):
                self.stop_event.wait(.5);continue
            with store.lock,store.db:
                row=store.db.execute("SELECT * FROM model_jobs WHERE room=? AND state='pending' ORDER BY ready,event_id LIMIT 1",(self.room,)).fetchone()
                if row and row['ready']<=time.time():
                    store.db.execute("UPDATE model_jobs SET state='model_running',attempts=attempts+1 WHERE room=? AND event_id=?",(self.room,row['event_id']))
                else:row=None
            if row is None:self.stop_event.wait(.25);continue
            event=json.loads(row['event']);start=time.monotonic()
            if time.time()-event['created']>600:
                self.set_job(event['id'],'expired');continue
            try:
                self.report(model_busy=True,processing_event_id=event['id'],last_model_error='')
                result=self.engine.process(event,recorded=True)
                self.report(last_model_seconds=round(time.monotonic()-start,2))
                if 'draft_id' in result:
                    self.set_job(event['id'],'sending')
                    self.report(last_draft_id=result['draft_id'])
                    self.send_result(result,event)
                    state=self.state().get('last_send_status')
                    self.set_job(event['id'],'sent' if state=='sent' else 'needs_review')
                else:self.set_job(event['id'],result['status'])
                self.report(last_total_seconds=round(time.monotonic()-start,2))
            except Exception as exc:
                error=str(exc)[:180] if isinstance(exc,UserError) else type(exc).__name__
                # Only retry model-stage connection/temporary server failures.
                retry=(isinstance(exc,UserError) and ('连接失败' in error or re.search(r'HTTP (429|50[234])',error)))
                with store.lock,store.db:
                    current=store.db.execute('SELECT state FROM model_jobs WHERE room=? AND event_id=?',(self.room,event['id'])).fetchone()
                    if retry and row['attempts']<2 and current['state']=='model_running':
                        store.db.execute("UPDATE model_jobs SET state='pending',ready=?,error=? WHERE room=? AND event_id=?",(time.time()+2**(row['attempts']+1),error,self.room,event['id']))
                    else:store.db.execute("UPDATE model_jobs SET state='failed',error=? WHERE room=? AND event_id=?",(error,self.room,event['id']))
                self.report(last_model_error=error)
            finally:self.report(model_busy=False,processing_event_id=None)
