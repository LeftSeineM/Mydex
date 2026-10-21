import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from lab import Engine, Settings, Store, UserError
from native_sender_bridge import NativeSender
from database_inbox import DatabaseInbox

class History:
    name='AI助手测试群'
    aliases={name}
    room='90000000003@chatroom'
    def __init__(self):self.body=None
    def message_paths(self):return ['message_3.db']
    def latest_cursor(self,path,group):return 1
    def fetch(self,path,group,after=None):
        events=[] if after is None or self.body is None else [{'content':self.body,'is_self':True,
            'created':time.time(),'id':'123456789'}]
        return {'events':events,'cursor':1}

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'store.db');self.settings=Settings(self.root/'settings.json')
        self.engine=Engine(self.settings,self.store);self.history=History();self.calls=[]
        def action(pid,command,body):
            self.calls.append(command)
            if command=='send':self.history.body=body
            return {'phase':2,'worker_thread':7,'return_code':0}
        self.sender=NativeSender(self.engine,self.root,native_action=action,reader_factory=lambda:self.history)
        self.sender.enabled=True;self.sender.pid=123
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def draft(self,source='wechat',room='AI助手测试群'):
        self.store.add(source,room,'小研','测试答案','assistant','request')
        return self.store.draft(room,'测试答案',source,'request')
    def test_success_requires_authenticated_new_self_server_row_and_never_resends(self):
        key=self.draft();result=self.sender.send_draft(key)
        self.assertTrue(result['server_record_verified'])
        self.assertEqual(self.store.pending()[0]['state'],'sent')
        with self.assertRaises(UserError):self.sender.send_draft(key)
        self.assertEqual(self.calls.count('send'),1)
    def test_authenticated_new_row_is_valid_when_server_clock_lags(self):
        fetch = self.history.fetch
        def delayed_clock(*args, **kwargs):
            result = fetch(*args, **kwargs)
            for event in result['events']:
                event['created'] -= 90
            return result
        self.history.fetch = delayed_clock
        result = self.sender.send_draft(self.draft())
        self.assertTrue(result['server_record_verified'])
        self.assertEqual(self.calls.count('send'), 1)
    def test_wrong_group_simulation_and_unlinked_draft_cannot_send(self):
        cases=[self.draft('simulation'),self.draft(room='其他群'),self.store.draft('AI助手测试群','旧草稿')]
        for key in cases:
            with self.assertRaises(UserError):self.sender.send_draft(key)
        self.assertNotIn('send',self.calls)
    def test_ambiguous_native_failure_is_unknown_and_not_retried(self):
        key=self.draft()
        def bad(pid,command,body):
            self.calls.append(command)
            if command=='send':raise OSError('client exited')
            return {'phase':2,'worker_thread':7}
        self.sender.native_action=bad
        with self.assertRaises(OSError):self.sender.send_draft(key)
        self.assertEqual(self.store.pending()[0]['state'],'unknown')
        with self.assertRaises(UserError):self.sender.send_draft(key)
        self.assertEqual(self.calls.count('send'),1)
    def test_disabled_or_restarted_client_preserves_draft(self):
        key=self.draft();self.sender.enabled=False
        with self.assertRaises(UserError):self.sender.send_draft(key)
        self.sender.enabled=True
        self.sender.native_action=lambda *args: {'phase':0,'worker_thread':0}
        with self.assertRaises(UserError):self.sender.send_draft(key)
        self.assertEqual(self.store.pending()[0]['state'],'draft')

    def test_pause_interrupts_pacing_before_native_send(self):
        key=self.draft()
        def pause(_):self.sender.enabled=False
        with patch.object(self.sender.guard,'delay',return_value=20), patch('native_sender_bridge.time.sleep',side_effect=pause):
            with self.assertRaises(UserError):self.sender.send_draft(key)
        self.assertNotIn('send',self.calls)
        self.assertEqual(self.store.pending()[0]['state'],'draft')

    def test_circuit_stops_later_replies_after_unknown_send(self):
        key=self.draft()
        def fail(pid,command,body):
            self.calls.append(command)
            if command=='send':raise OSError('unknown outcome')
            return {'phase':2,'worker_thread':7}
        self.sender.native_action=fail
        with self.assertRaises(OSError):self.sender.send_draft(key)
        self.store.add('wechat','AI助手测试群','小研','另一回复','assistant','request-2')
        second=self.store.draft('AI助手测试群','另一回复','wechat','request-2')
        with self.assertRaises(UserError):self.sender.send_draft(second)
        self.assertEqual(self.calls.count('send'),1)
        self.assertTrue(self.sender.state(fresh=True)['send_guard']['blocked'])

    def test_reused_pid_cannot_invoke_native_code(self):
        import psutil
        self.sender.native_action=None
        (self.root/'native-sender-settings.json').write_text(json.dumps({
            'pid':self.sender.pid,'process_created':100,'account_verified':True}),encoding='utf-8')
        with patch.object(psutil,'Process') as process:
            process.return_value.create_time.return_value=200
            with self.assertRaises(UserError):self.sender.action('send','not delivered')
    def test_automatic_path_requires_new_verified_incoming_at(self):
        inbox=DatabaseInbox(self.engine,self.root,sender=self.sender)
        result={'draft_id':'fake'}
        event={'source':'wechat','created':time.time(),'mention_verified':True,'is_self':False}
        with patch.object(self.sender,'send_draft',return_value={'status':'sent'}) as send:
            for bad in ({**event,'source':'simulation'},{**event,'is_self':True},
                        {**event,'mention_verified':False},{**event,'created':time.time()-4000}):
                inbox.send_result(result,bad)
            send.assert_not_called()
            inbox.send_result(result,event)
            send.assert_called_once_with('fake')

    def test_server_id_update_on_same_local_row_is_checked_again(self):
        key=self.draft()
        polls=[]
        def fetch(path,group,after=None):
            if after is None:return {'events':[],'cursor':10}
            polls.append(after)
            if after>10:return {'events':[],'cursor':11}
            event={'content':self.history.body,'is_self':True,'created':time.time(),
                   'id':'message_3.db:11' if len(polls)==1 else '123456789'}
            return {'events':[event],'cursor':11}
        self.history.fetch=fetch
        self.history.latest_cursor=lambda path,group:10
        with patch('native_sender_bridge.time.sleep'):
            result=self.sender.send_draft(key)
        self.assertTrue(result['server_record_verified'])
        self.assertEqual(polls,[10,10])

if __name__=='__main__':unittest.main()
