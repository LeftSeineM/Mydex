from unittest.mock import patch
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock

from desktop_operator import DesktopBridge
from lab import Store, UserError


class DesktopTests(unittest.TestCase):
    def setUp(self):
        # Isolate policy and clock from the original machine's private state.
        for target, value in [('account_assistant.load_scope', {'all_direct_messages': True}), ('account_assistant.replies_allowed', True)]:
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bridge = DesktopBridge(self.root)
        self.entry = {'peer': 'operator', 'kind': 'direct', 'configured_name': 'private',
                      'authenticated_table': 'Msg_' + hashlib.md5(b'operator').hexdigest()}
        self.cfg = {'sender_account': 'operator', 'receiving_account': 'self', 'enabled': True,
                    'activated_at': time.time()-1, 'pid': 123, 'process_created': 123.0}
        self.authority = {**self.cfg, 'authority_level': 'same_user_instruction_authority_as_owner'}
        self.save()
        self.event = {'id': '123', 'source': 'wechat', 'room': 'private', 'sender': 'operator',
                      'content': 'Current requirement', 'type': 'text', 'is_self': False, 'created': time.time()}
        self.store = Store(self.root / 'history.db')

    def save(self):
        for name, value in [('desktop-operator.json', self.cfg), ('operator-authority.json', self.authority),
                            ('session.json', {'pid':123, 'created':123.0})]:
            (self.root/name).write_text(json.dumps(value), encoding='utf-8')

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def capture(self):
        self.assertTrue(self.bridge.capture(self.event, self.entry, 'self'))
        return self.bridge.pending()[0]['id']

    def test_only_exact_direct_identity_is_selected(self):
        for entry in ({**self.entry,'peer':'imposter'}, {**self.entry,'kind':'group'}):
            self.assertFalse(self.bridge.capture(self.event, entry, 'self'))
        self.assertEqual(self.bridge.pending(), [])

    def test_mismatched_account_and_authority_do_not_fall_back(self):
        with self.assertRaises(UserError):
            self.bridge.capture(self.event, self.entry, 'other-account')
        self.authority['sender_account'] = 'changed'
        self.save()
        with self.assertRaises(UserError):
            self.bridge.capture(self.event, self.entry, 'self')

    def test_new_wechat_session_requires_bridge_revalidation(self):
        (self.root/'session.json').write_text(json.dumps({'pid':456,'created':456.0}),encoding='utf-8')
        with self.assertRaises(UserError):self.bridge.capture(self.event,self.entry,'self')

    def test_self_wrong_sender_old_and_nonserver_events_never_capture(self):
        for change in ({'is_self':True}, {'sender':'other'}, {'created':time.time()-2},
                       {'id':'local:1'}, {'source':'simulation'}, {'room':'group'}):
            self.assertTrue(self.bridge.capture({**self.event,**change}, self.entry, 'self'))
        self.assertEqual(self.bridge.pending(), [])

    def test_duplicate_capture_and_single_claim(self):
        task = self.capture()
        self.capture()
        self.assertEqual(len(self.bridge.pending()),1)
        self.assertEqual(self.bridge.claim(task)['content'], self.event['content'])
        with self.assertRaises(UserError):self.bridge.claim(task)
        replacement = DesktopBridge(self.root)
        with self.assertRaises(UserError):replacement.claim(task)

    def test_stale_pending_is_expired_not_executed(self):
        task = self.capture()
        with self.bridge.db() as db:db.execute('UPDATE requests SET created=?', (time.time()-1801,))
        self.assertEqual(self.bridge.pending(), [])
        with self.assertRaises(UserError):self.bridge.claim(task)

    def test_pending_survives_one_fifteen_minute_poll_interval(self):
        task = self.capture()
        with self.bridge.db() as db:db.execute('UPDATE requests SET created=?', (time.time()-901,))
        self.assertEqual(self.bridge.pending()[0]['id'], task)
        self.assertEqual(self.bridge.claim(task)['id'], task)

    def test_restart_never_replays_queued_instruction_or_reply(self):
        task=self.capture()
        self.bridge.start_run()
        self.assertEqual(self.bridge.status(task)['state'],'expired')
        self.event['id']='125'
        task=self.capture()
        self.bridge.claim(task)
        self.bridge.complete(task,'Result',self.store,'Mydex')
        self.bridge.start_run()
        self.assertEqual(self.bridge.status(task)['state'],'needs_review')
        sender=Mock()
        self.bridge.deliver_one(self.entry,'self',sender)
        sender.send_draft.assert_not_called()

    def test_fifo_claiming_and_quoted_content_kind_preserved(self):
        first = self.capture()
        self.event.update(id='124',type='quote',created=time.time()+.1)
        second = self.capture()
        rows = self.bridge.pending()
        self.assertEqual(rows[1]['kind'],'quote')
        with self.assertRaises(UserError):self.bridge.claim(rows[1]['id'])
        self.bridge.claim(first)

    def test_complete_uses_existing_native_draft_and_proof(self):
        task = self.capture()
        self.bridge.claim(task)
        self.assertEqual(self.bridge.complete(task,'A truthful result',self.store,'Mydex'), {'state':'ready'})
        sender = Mock()
        sender.send_draft.return_value = {'status':'sent','server_record_verified':True,'reply_event_id':'456'}
        self.bridge.deliver_one(self.entry,'self',sender)
        self.bridge.deliver_one(self.entry,'self',sender)
        sender.send_draft.assert_called_once()
        self.assertTrue(self.bridge.status(task)['server_record_verified'])
        with self.assertRaises(UserError):self.bridge.complete(task,'Again',self.store,'Mydex')

    def test_uncertain_send_is_not_retried(self):
        task = self.capture()
        self.bridge.claim(task)
        self.bridge.complete(task,'Result',self.store,'Mydex')
        sender = Mock()
        sender.send_draft.side_effect = TimeoutError()
        self.bridge.deliver_one(self.entry,'self',sender)
        self.bridge.deliver_one(self.entry,'self',sender)
        sender.send_draft.assert_called_once()
        self.assertEqual(self.bridge.status(task)['state'],'needs_review')

    def test_crash_with_existing_draft_requires_review(self):
        task = self.capture()
        self.bridge.claim(task)
        self.store.draft('private','Previous result','wechat','123')
        self.assertEqual(self.bridge.complete(task,'Result',self.store,'Mydex'),{'state':'needs_review'})

    def test_group_inbox_and_other_private_messages_keep_qwen_queue(self):
        from account_assistant import AccountInbox
        from lab import Engine,Settings
        settings=Settings(self.root/'settings.json')
        settings.update({'group':'private'})
        engine=Engine(settings,self.store)
        reader=Mock()
        reader.message_paths.return_value=['messages']
        entry={**self.entry,'registered_since':time.time()-1,'runtime_started':time.time()-1}
        inbox=AccountInbox(engine,self.root,entry=entry,reader_factory=lambda:reader,
                           desktop_bridge=self.bridge,receiving_account='self')
        inbox.consider_event(self.event)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM model_jobs').fetchone()[0],0)
        entry['peer']='other'
        inbox.consider_event({**self.event,'sender':'other','id':'124'})
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM model_jobs').fetchone()[0],1)


if __name__ == '__main__':unittest.main()
