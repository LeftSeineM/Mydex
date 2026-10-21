import json,tempfile,time,unittest
from pathlib import Path
from lab import Engine,Settings,Store
from conversation_queue import ConversationInbox,is_question

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'history.db');self.settings=Settings(self.root/'settings.json')
        self.settings.update({'conversation_enabled':True})
        self.engine=Engine(self.settings,self.store)
        self.inbox=ConversationInbox(self.engine,self.root)
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def event(self,id='1',**changes):
        return {'id':id,'source':'wechat','room':'AI助手测试群','sender':'member',
                'content':'这个题怎么做？','type':'text','created':time.time(),'is_self':False,**changes}
    def jobs(self):return self.store.db.execute('SELECT * FROM model_jobs ORDER BY event_id').fetchall()
    def test_ordinary_question_is_eligible_without_faking_at(self):
        self.inbox.consider_event(self.event())
        event=json.loads(self.jobs()[0]['event'])
        self.assertTrue(event['conversation_verified']);self.assertFalse(event.get('mention_verified',False))
    def test_own_message_and_short_chatter_do_not_echo(self):
        self.inbox.consider_event(self.event(is_self=True))
        self.inbox.consider_event(self.event('2',content='哈哈哈哈'))
        self.assertEqual(self.jobs(),[])
    def test_pending_jobs_survive_restart_without_duplicate(self):
        self.inbox.consider_event(self.event())
        other=ConversationInbox(self.engine,self.root)
        other.consider_event(self.event())
        self.assertEqual(len(self.jobs()),1)
    def test_related_questions_merge_but_other_member_is_independent(self):
        for e in (self.event(),self.event('2'),self.event('3',sender='another')):self.inbox.consider_event(e)
        self.assertEqual([j['state'] for j in self.jobs()],['merged','pending','pending'])
    def test_explicit_requests_do_not_get_member_cooldown_dropped(self):
        for i in range(4):self.inbox.consider_event(self.event(str(i),mention_verified=True))
        self.assertEqual([j['state'] for j in self.jobs()],['pending']*4)
    def test_mentions_only_answers_chatter_mentions_but_ignores_unmentioned_questions(self):
        self.settings.update({'conversation_enabled':False})
        self.inbox.consider_event(self.event('ordinary',content='今天怎么安排？'))
        for i in range(3):
            self.inbox.consider_event(self.event(str(i),content='@M 哈哈',mention_verified=True))
        rows=self.jobs()
        self.assertEqual(len(rows),3)
        self.assertTrue(all(row['state']=='pending' for row in rows))
        self.assertTrue(all(json.loads(row['event'])['mention_verified'] for row in rows))
    def test_uncertain_send_never_retries_on_restart(self):
        self.inbox.consider_event(self.event())
        with self.store.db:self.store.db.execute("UPDATE model_jobs SET state='sending'")
        ConversationInbox(self.engine,self.root)
        self.assertEqual(self.jobs()[0]['state'],'needs_review')

if __name__=='__main__':unittest.main()
