from unittest.mock import patch
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from account_assistant import AccountInbox
from lab import Engine, Settings, Store


class LocalRuntimeTests(unittest.TestCase):
    def setUp(self):
        # Isolate policy and clock from the original machine's private state.
        for target, value in [('account_assistant.load_scope', {'all_direct_messages': True}), ('account_assistant.replies_allowed', True)]:
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'history.db')
        self.settings = Settings(self.root / 'settings.json')
        self.settings.update({'provider': 'mock', 'group': 'test', 'conversation_enabled': False})
        self.engine = Engine(self.settings, self.store)
        self.since = time.time() - 5
        self.entry = {'kind': 'group', 'peer': '123456@chatroom', 'registered_since': self.since - 100,
                      'runtime_started': self.since, 'previously_enabled': True}
        self.inbox = self.make_inbox()

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def make_inbox(self):
        return AccountInbox(self.engine, self.root, entry=self.entry,
                            reader_factory=lambda: SimpleNamespace(message_paths=lambda: []))

    def event(self, **changes):
        return {'id': 'fresh', 'source': 'wechat', 'room': 'test', 'sender': 'member',
                'content': 'test question', 'type': 'text', 'created': time.time(),
                'is_self': False, 'mention_verified': True, **changes}

    def jobs(self):
        return list(self.store.db.execute('SELECT state FROM model_jobs'))

    def test_restart_does_not_reply_to_recent_offline_mentions(self):
        self.inbox.consider_event(self.event(created=self.since - 1))
        self.assertEqual(self.jobs(), [])
        self.inbox.consider_event(self.event())
        self.assertEqual(len(self.jobs()), 1)

    def test_previous_model_jobs_expire_and_unknown_sends_stay_held(self):
        self.inbox.consider_event(self.event())
        self.make_inbox()
        self.assertEqual(self.jobs()[0]['state'], 'expired')
        with self.store.db:
            self.store.db.execute("UPDATE model_jobs SET state='sending'")
        self.make_inbox()
        self.assertEqual(self.jobs()[0]['state'], 'needs_review')

    def test_plain_group_messages_and_own_messages_do_not_trigger(self):
        self.inbox.consider_event(self.event(mention_verified=False))
        self.inbox.consider_event(self.event(is_self=True))
        self.assertEqual(self.jobs(), [])

    def test_direct_message_must_be_new_and_from_bound_peer(self):
        self.entry.update(kind='direct', peer='member')
        inbox = self.make_inbox()
        inbox.consider_event(self.event(created=self.since - 1, mention_verified=False))
        inbox.consider_event(self.event(sender='another', mention_verified=False))
        self.assertEqual(self.jobs(), [])
        inbox.consider_event(self.event(mention_verified=False))
        inbox.consider_event(self.event(mention_verified=False))
        self.assertEqual(len(self.jobs()), 1)


if __name__ == '__main__':
    unittest.main()
