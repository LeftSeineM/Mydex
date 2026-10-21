from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest

from history_context import CN, compose, query_plan, retrieve
from lab import Store, Settings


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        self.store=Store(root/'history.db');self.cfg=Settings(root/'settings.json').get()
        self.now=datetime(2026,10,7,23,0,tzinfo=CN).timestamp()
    def tearDown(self):self.store.db.close();self.temp.cleanup()
    def add(self,key,text,when=None,sender='member',room='A',source='wechat',role='user'):
        self.store.add(source,room,sender,text,role,str(key),when or self.now)
    def test_yesterday_filters_in_beijing_time_and_keeps_question_last(self):
        self.add('old','昨天下午确认周五交付',self.now-86400)
        self.add('today','今天完全无关的消息')
        self.add('request','@助手 总结昨天聊了什么')
        rows,scope=compose(self.store,'wechat','A','@助手 总结昨天聊了什么','request',self.cfg,self.now)
        text=json.dumps(rows,ensure_ascii=False)
        self.assertIn('确认周五交付',text);self.assertNotIn('完全无关',text)
        self.assertEqual(rows[-1]['event_id'],'request')
        self.assertEqual(scope['query_start'],'2026-10-06T00:00:00+08:00')
    def test_laugh_counts_all_rows_not_recent_sample_and_never_other_room(self):
        for n in range(70):self.add(n,'哈哈哈哈',self.now-10000-n,sender='A-user')
        for n in range(1100):self.add('recent-'+str(n),'不含笑声的普通讨论',self.now-1000+n/2,sender='B-user')
        self.add('other','哈哈',room='other')
        self.add('sim','哈哈',source='simulation')
        self.add('bot','Mydex：哈哈')
        self.add('request','@助手 谁最爱发连续哈哈')
        rows,scope=retrieve(self.store,'wechat','A','@助手 谁最爱发连续哈哈','request',limit=5,now=self.now)
        self.assertEqual(scope['statistics']['matched_messages'],70)
        self.assertEqual(scope['statistics']['ranking'][0]['count'],70)
        self.assertEqual(len(rows),5)
        self.assertEqual(scope['searched_user_messages'],1170)
    def test_topic_search_reaches_past_latest_thousand_and_survives_context_budget(self):
        self.add('old','PPT模板用了蓝色标题',self.now-100000)
        for n in range(1100):self.add(n,'最近消息'*200,self.now-1000+n/2)
        self.add('request','@助手 之前PPT模板什么样')
        rows,scope=compose(self.store,'wechat','A','@助手 之前PPT模板什么样','request',{**self.cfg,'summary_max_chars':4000},self.now)
        self.assertIn('PPT模板用了蓝色标题',json.dumps(rows,ensure_ascii=False))
        self.assertEqual(rows[-1]['event_id'],'request')
    def test_message_count_excludes_bot_echo_and_current_question(self):
        self.add('a','消息',sender='one');self.add('b','【图片消息：正文尚未解析】',sender='one')
        self.add('c','Mydex：答案',sender='owner')
        self.add('d','答案',role='assistant');self.add('request','谁发消息最多')
        _,scope=retrieve(self.store,'wechat','A','谁发消息最多','request',now=self.now)
        self.assertEqual(scope['statistics']['matched_messages'],2)
        self.assertEqual(scope['statistics']['ranking'][0]['count'],2)
    def test_no_matches_not_replaced_with_unrelated_recent_chat(self):
        self.add('today','刚刚的无关讨论');self.add('request','总结昨天群聊')
        rows,scope=compose(self.store,'wechat','A','总结昨天群聊','request',self.cfg,self.now)
        self.assertEqual(scope['matched_messages'],0)
        self.assertEqual(len(rows),1)
    def test_long_current_question_retained(self):
        question='总结之前的群聊'+'问题'*3000
        self.add('request',question)
        rows,_=compose(self.store,'wechat','A',question,'request',{**self.cfg,'summary_max_chars':4000},self.now)
        self.assertEqual(rows[-1]['event_id'],'request')
        self.assertLess(len(rows[-1]['content']),4000)
    def test_night_and_explicit_date(self):
        plan=query_plan('总结昨天晚上群聊',self.now)
        self.assertEqual(datetime.fromtimestamp(plan['start'],CN).hour,18)
        plan=query_plan('总结2026年8月10日聊过的内容',self.now)
        self.assertEqual(datetime.fromtimestamp(plan['start'],CN).date().isoformat(),'2026-08-10')

    def test_temporary_id_does_not_double_count_confirmed_physical_row(self):
        self.add('message_3.db:8','哈哈',sender='one')
        self.add('123456','哈哈',sender='one')
        self.add('message_3.db:8','哈哈',sender='one',room='other')
        self.store.reconcile_local_id({'id':'123456','database':'message_3.db','local_id':8,
                                       'room':'A','sender':'one','content':'哈哈'})
        _,scope=retrieve(self.store,'wechat','A','谁最爱哈哈','request',now=self.now)
        self.assertEqual(scope['statistics']['matched_messages'],1)
        self.assertEqual(len(self.store.history('wechat','other')),1)

    def test_answered_temporary_request_is_not_rewritten(self):
        self.add('message_3.db:8','问题');self.add('message_3.db:8','回答',role='assistant')
        self.store.reconcile_local_id({'id':'123456','database':'message_3.db','local_id':8,
                                       'room':'A','sender':'member','content':'问题'})
        self.assertEqual({r['event_id'] for r in self.store.history('wechat','A')},{'message_3.db:8'})


if __name__=='__main__':unittest.main()
