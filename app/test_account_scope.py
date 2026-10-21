from unittest.mock import patch
import json,tempfile,time,unittest
from pathlib import Path
from lab import Settings,Store,Engine
from account_scope import peer_kind,validate_recipient
from account_assistant import AccountInbox
from account_scope import stable_read,SnapshotChanged
from unittest.mock import Mock,patch

class SnapshotRecoveryTests(unittest.TestCase):
    def test_live_reader_snapshot_conflict_retries_then_recovers(self):
        from history_reader import SnapshotChanged as LiveSnapshotChanged
        operation=Mock(side_effect=[LiveSnapshotChanged(),LiveSnapshotChanged(),{'verified':True}])
        with patch('account_scope.time.sleep'):
            self.assertEqual(stable_read(operation),{'verified':True})
        self.assertEqual(operation.call_count,3)

    def test_persistent_snapshot_conflict_is_bounded(self):
        operation=Mock(side_effect=SnapshotChanged())
        with patch('account_scope.time.sleep'):
            with self.assertRaises(SnapshotChanged):stable_read(operation)
        self.assertEqual(operation.call_count,4)

    def test_authentication_failure_is_not_retried(self):
        operation=Mock(side_effect=ValueError('Page authentication failed'))
        with self.assertRaises(ValueError):stable_read(operation)
        operation.assert_called_once()

class FakeReader:
    def message_paths(self):return ['message_0.db']

class BaselineReader(FakeReader):
    aliases={'AI助手测试群'}
    name='AI助手测试群'
    account='owner'
    def __init__(self,events):
        self.paths=['message_0.db']
        self.events_by_path={'message_0.db':[{**event,'local_id':index} for index,event in enumerate(events,1)]}
    def message_paths(self):return self.paths
    def fingerprint(self,path):return 1
    def fetch(self,path,group,after=None):
        events=self.events_by_path[path]
        rows=events if after is None else [event for event in events if event['local_id']>after]
        return {'events':rows,'cursor':max([event['local_id'] for event in events] or [0]),
                'stored_rows':len(events),'read_rows':len(rows),'rejected':0}

class Tests(unittest.TestCase):
    def setUp(self):
        # Isolate policy and clock from the original machine's private state.
        for target, value in [('account_assistant.load_scope', {'all_direct_messages': True}), ('account_assistant.replies_allowed', True)]:
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'history.db');self.settings=Settings(self.root/'settings.json')
        self.engine=Engine(self.settings,self.store)
        self.entry={'peer':'wxid_test','kind':'direct','registered_since':time.time()-1,'previously_enabled':False}
        self.inbox=AccountInbox(self.engine,self.root,entry=self.entry,reader_factory=FakeReader)
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def event(self,**changes):
        return {'id':'1','source':'wechat','room':'AI助手测试群','sender':'wxid_test','content':'你好',
                'type':'text','created':time.time(),'is_self':False,**changes}
    def jobs(self):return self.store.db.execute('SELECT * FROM model_jobs').fetchall()
    def test_private_text_queues_without_mention(self):
        self.inbox.consider_event(self.event())
        self.assertTrue(json.loads(self.jobs()[0]['event'])['direct_verified'])
    def test_old_messages_self_and_wrong_peer_never_reply(self):
        for changes in ({'created':time.time()-20},{'is_self':True},{'sender':'somebody_else'},{'type':'system'}):
            self.inbox.consider_event(self.event(**changes))
        self.assertEqual(self.jobs(),[])
    def test_new_groups_still_require_true_at(self):
        self.entry['kind']='group'
        self.inbox.consider_event(self.event())
        self.assertEqual(self.jobs(),[])
        self.inbox.consider_event(self.event(mention_verified=True))
        self.assertEqual(len(self.jobs()),1)

    def test_first_verified_at_in_newly_discovered_group_is_processed(self):
        now=time.time()
        entry={**self.entry,'kind':'group','registered_since':now-20,'runtime_started':now-10}
        events=[self.event(id='1',created=now-11,mention_verified=True),
                self.event(id='2',created=now,mention_verified=True),
                self.event(id='3',created=now,mention_verified=False)]
        reader=BaselineReader(events)
        inbox=AccountInbox(self.engine,self.root,entry=entry,reader_factory=lambda:reader)
        inbox.cycle(reader)
        self.assertEqual([job['event_id'] for job in self.jobs()],['2'])
        inbox.cycle(reader)
        self.assertEqual(len(self.jobs()),1)

    def test_first_verified_at_in_new_message_shard_is_not_lost(self):
        now=time.time()
        entry={**self.entry,'kind':'group','registered_since':now-20,'runtime_started':now-10}
        reader=BaselineReader([])
        inbox=AccountInbox(self.engine,self.root,entry=entry,reader_factory=lambda:reader)
        inbox.cycle(reader)
        reader.paths.append('message_1.db')
        reader.events_by_path['message_1.db']=[
            {**self.event(id='1',created=now-11,mention_verified=True),'local_id':1},
            {**self.event(id='2',created=now,mention_verified=True),'local_id':2},
            {**self.event(id='3',created=now,mention_verified=False),'local_id':3},
        ]
        inbox.cycle(reader)
        self.assertEqual([job['event_id'] for job in self.jobs()],['2'])

    def test_baseline_does_not_run_direct_commands_or_unverified_group_ats(self):
        now=time.time()
        entry={**self.entry,'kind':'direct','registered_since':now-20,'runtime_started':now-10}
        reader=BaselineReader([])
        inbox=AccountInbox(self.engine,self.root,entry=entry,reader_factory=lambda:reader)
        inbox.cycle(reader)
        reader.paths.append('message_1.db')
        reader.events_by_path['message_1.db']=[
            {**self.event(id='1',created=now,mention_verified=True),'local_id':1},
        ]
        inbox.cycle(reader)
        self.assertEqual(self.jobs(),[])
    def test_private_attachments_get_honest_placeholder_context(self):
        self.inbox.consider_event(self.event(type='attachment',content='【群文件】方案.pdf，文件正文尚未读取。'))
        self.assertEqual(len(self.jobs()),1)
    def test_system_subscriptions_and_invalid_targets_excluded(self):
        for peer in ('filehelper','weixin','gh_example','abc@evil','bad/peer',''):
            self.assertIsNone(peer_kind(peer))
        self.assertEqual(peer_kind('90000000000@chatroom'),'group')
        self.assertEqual(peer_kind('legacy.friend'),'direct')

if __name__=='__main__':unittest.main()
