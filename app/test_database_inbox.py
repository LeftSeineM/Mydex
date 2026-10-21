import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from lab import Engine, Settings, Store
from database_inbox import DatabaseInbox
from history_reader import app_fields, normalize_row


class Backend:
    def __init__(self): self.calls = []
    def reply(self, cfg, messages):
        self.calls.append(messages)
        return '已总结真实群聊。'


class Reader:
    aliases = {'AI助手测试群'}
    name = 'AI助手测试群'
    account = 'owner'
    def __init__(self):
        self.rows = []
        self.stamp = 0
        self.paths = ['message_3.db']
    def message_paths(self): return self.paths
    def fingerprint(self, path): return self.stamp
    def fetch(self, path, group, after=None):
        rows = self.rows if after is None else [r for r in self.rows if r['local_id'] > after]
        return {'events': rows, 'cursor': max([r['local_id'] for r in self.rows] or [0]),
                'stored_rows': len(self.rows), 'read_rows': len(rows), 'rejected': 0}
    def add(self, content, mentioned=False, kind='text', self_message=False):
        n = len(self.rows) + 1
        self.rows.append({'id': str(n), 'local_id': n, 'source': 'wechat', 'room': self.name,
                          'sender': 'owner' if self_message else 'member', 'content': content,
                          'created': time.time(), 'type': kind,
                          'mention_verified': mentioned, 'is_self': self_message})
        self.stamp += 1


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.settings = Settings(self.root/'settings.json')
        self.store = Store(self.root/'records.db')
        self.backend = Backend()
        self.engine = Engine(self.settings, self.store, self.backend)
        self.inbox = DatabaseInbox(self.engine, self.root)
        self.reader = Reader()
    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def test_bound_client_health_does_not_scan_all_processes(self):
        self.inbox.sender = Mock(pid=123, session={'created': 456})
        proc = Mock()
        proc.create_time.return_value = 456
        proc.is_running.return_value = True
        proc.name.return_value = 'Weixin.exe'
        with patch('psutil.Process', return_value=proc), patch('psutil.process_iter') as scan:
            self.assertTrue(self.inbox.client_online())
            scan.assert_not_called()

    def test_reused_bound_pid_is_offline(self):
        self.inbox.sender = Mock(pid=123, session={'created': 456})
        proc = Mock()
        proc.create_time.return_value = 789
        with patch('psutil.Process', return_value=proc), patch('psutil.process_iter') as scan:
            self.assertFalse(self.inbox.client_online())
            scan.assert_not_called()
    def test_baseline_is_archived_without_replaying_mentions(self):
        self.reader.add('@小研 总结', True)
        self.reader.add('【文件】研究.csv', kind='attachment')
        self.inbox.cycle(self.reader)
        self.assertEqual(self.inbox.state()['archived'], 2)
        self.assertEqual(self.inbox.summary_queue.qsize(), 0)
        self.assertFalse(self.backend.calls)

    def test_restart_never_replays_since_group_enrollment(self):
        self.inbox.initial_since=time.time()-86400
        self.reader.add('@账号 总结', True)
        self.inbox.cycle(self.reader)
        self.assertTrue(self.inbox.summary_queue.empty())
        self.assertEqual(self.inbox.state()['archived'],1)

    def test_burst_preserves_history_but_caps_model_queue(self):
        self.inbox.cycle(self.reader)
        for n in range(20):
            self.reader.add('@账号 问题 '+str(n), True)
            self.reader.rows[-1]['sender']='member-'+str(n)
        self.inbox.cycle(self.reader)
        self.assertEqual(self.inbox.summary_queue.qsize(),8)
        self.assertEqual(len(self.store.history('wechat',self.reader.name,100)),20)
        self.assertEqual(self.inbox.state()['skipped_mentions'],12)

    def test_stale_synced_at_is_recorded_without_reply(self):
        self.inbox.cycle(self.reader)
        self.reader.add('@账号 旧问题', True)
        self.reader.rows[-1]['created']=time.time()-601
        self.inbox.cycle(self.reader)
        self.assertTrue(self.inbox.summary_queue.empty())
        self.assertEqual(self.inbox.state()['last_skip_reason'],'stale_mention')
    def test_live_message_and_verified_at_reach_real_history(self):
        self.inbox.cycle(self.reader)
        self.reader.add('明天上午讨论项目')
        self.reader.add('@账号 总结', True)
        self.inbox.cycle(self.reader)
        self.assertEqual(self.inbox.state()['new_messages'], 2)
        event = self.inbox.summary_queue.get_nowait()
        result = self.engine.process(event,recorded=True)
        self.assertIn('draft_id', result)
        self.assertIn('明天上午讨论项目', json.dumps(self.backend.calls, ensure_ascii=False))
        self.inbox.cycle(self.reader)
        self.assertEqual(self.inbox.summary_queue.qsize(), 0)
        self.assertEqual(len(self.store.pending()), 1)
        self.assertEqual(self.engine.process(event,recorded=True)['status'],'duplicate')
    def test_self_mention_and_new_old_shard_never_call_model(self):
        self.inbox.cycle(self.reader)
        self.reader.add('@小研 总结', True, self_message=True)
        self.inbox.cycle(self.reader)
        self.reader.paths.append('message_0.db')
        self.inbox.cycle(self.reader)
        self.assertEqual(self.inbox.summary_queue.qsize(), 0)
        self.assertFalse(self.backend.calls)
    def test_binding_change_fails_closed(self):
        self.settings.update({'group': '另一个群'})
        with self.assertRaises(Exception): self.inbox.cycle(self.reader)
        self.assertFalse(self.store.history('wechat', '另一个群'))

    def test_explicit_live_self_command_works_and_reply_never_loops(self):
        self.reader.add('#小研 过去的命令', self_message=True)
        self.inbox.cycle(self.reader)
        self.assertTrue(self.inbox.summary_queue.empty())
        self.reader.add('#小研 只回复测试成功', self_message=True)
        self.inbox.cycle(self.reader)
        event=self.inbox.summary_queue.get_nowait()
        self.assertTrue(event['self_command_verified'])
        result=self.engine.process(event,recorded=True)
        self.assertIn('draft_id',result)
        self.reader.add('小研：测试成功',self_message=True)
        self.inbox.cycle(self.reader)
        self.assertTrue(self.inbox.summary_queue.empty())
        self.assertEqual(len(self.backend.calls),1)


class MessageTests(unittest.TestCase):
    def test_app_file_tokens_are_not_exported(self):
        body = '<msg><appmsg><title>x.csv</title><type>6</type><appattach><totallen>10</totallen><fileext>csv</fileext><filemd5>'+'a'*32+'</filemd5><aeskey>PRIVATE</aeskey><cdnattachurl>PRIVATE</cdnattachurl></appattach></appmsg></msg>'
        value = app_fields(body)
        self.assertEqual(value['size'], 10)
        self.assertNotIn('PRIVATE', json.dumps(value))
        with self.assertRaises(ValueError): app_fields('<!DOCTYPE x>'+body)
    def test_quote_and_native_at_are_preserved(self):
        source = '<msgsource><atuserlist><![CDATA[owner]]></atuserlist></msgsource>'
        body = '<msg><appmsg><type>57</type><title>明天确认</title><refermsg><displayname>M</displayname><content>周五开会</content></refermsg></appmsg></msg>'
        value = normalize_row((1, 20, 49, 1788782246, 'member', body, None, source, 1), '10@chatroom', '群', 'owner', 'message_3.db')
        self.assertTrue(value['mention_verified'])
        self.assertEqual(value['type'], 'quote')
        self.assertIn('周五开会', value['content'])
    def test_media_does_not_import_keys_from_xml(self):
        value = normalize_row((1, 20, 3, 1788782246, 'member', '<img aeskey="PRIVATE"/>', None, '', 1), '10@chatroom', '群', 'owner', 'message_3.db')
        self.assertEqual(value['type'], 'media')
        self.assertNotIn('PRIVATE', value['content'])

if __name__ == '__main__': unittest.main()
