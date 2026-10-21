import tempfile
from contextlib import closing
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
import manage


class StatusTests(unittest.TestCase):
    def test_stale_runtime_requires_current_running_child(self):
        self.assertFalse(manage.runtime_stalled({'phase':'running','at':100},101,281))
        self.assertTrue(manage.runtime_stalled({'phase':'running','at':100},99,281))
        self.assertFalse(manage.runtime_stalled({'phase':'stopping','at':100},99,500))
        self.assertFalse(manage.runtime_stalled({'phase':'running','at':100},101,500))

    def test_uncertain_delivery_only_flags_in_flight_attempts(self):
        with tempfile.TemporaryDirectory() as root, patch.object(manage,'DATA',Path(root)):
            with closing(sqlite3.connect(Path(root)/'history.sqlite3')) as db:
                with db:
                    db.execute('CREATE TABLE outbox (state TEXT)')
                    db.execute('CREATE TABLE send_attempts (outcome TEXT)')
                    db.execute("INSERT INTO outbox VALUES ('draft')")
            self.assertFalse(manage.uncertain_delivery())
            with closing(sqlite3.connect(Path(root)/'history.sqlite3')) as db:
                with db:
                    db.execute("INSERT INTO send_attempts VALUES ('sending')")
            self.assertTrue(manage.uncertain_delivery())

    def test_start_waits_for_stopping_supervisor(self):
        with patch.object(manage,'supervisor_running',side_effect=[True,True,False]), \
                patch.object(manage.time,'sleep') as sleep:
            self.assertTrue(manage.wait_for_supervisor_exit())
            self.assertEqual(sleep.call_count,2)

    def test_stopping_supervisor_wait_is_bounded(self):
        with patch.object(manage,'supervisor_running',return_value=True), \
                patch.object(manage.time,'monotonic',side_effect=[0,31]):
            self.assertFalse(manage.wait_for_supervisor_exit())

    def test_transient_reader_lock_recovers(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'status.json'
            original = Path.replace
            attempts = []
            def replace(path, destination):
                attempts.append(1)
                if len(attempts) < 3:
                    raise PermissionError('reader lock')
                return original(path, destination)
            with patch.object(manage, 'DATA', Path(root)), patch.object(manage, 'STATUS', target), \
                    patch.object(Path, 'replace', replace), patch.object(manage.time, 'sleep'):
                value = manage.report('running')
            self.assertTrue(target.exists())
            self.assertEqual(len(attempts), 3)
            self.assertNotIn('status_write_deferred', value)

    def test_persistent_status_lock_does_not_orphan_child(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(manage, 'DATA', Path(root)), patch.object(manage, 'STATUS', Path(root)/'status.json'), \
                    patch.object(Path, 'replace', side_effect=PermissionError('locked')) as replace, \
                    patch.object(manage.time, 'sleep'):
                value = manage.report('running')
            self.assertTrue(value['status_write_deferred'])
            self.assertEqual(replace.call_count, 6)


if __name__ == '__main__':
    unittest.main()
