import tempfile
import json
import threading
import unittest
from pathlib import Path

from lab import Store
from send_guard import MentionGate, SendGuard, SendHeld, POLICY


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)/'history.db'
        self.store = Store(self.path)
        self.now = 1000000
        self.guard = SendGuard(self.store, lambda:self.now)

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def draft(self, number=1, room='A', content=None):
        return dict(id=str(number),room=room,event_id=str(number),
                    content=content or 'reply '+str(number),created=self.now)

    def sent(self, draft):
        self.guard.reserve(draft)
        self.guard.finish(draft['id'],'sent')

    def test_cross_group_and_group_gaps_persist_across_restart(self):
        self.sent(self.draft())
        self.assertEqual(self.guard.delay(self.draft(2,room='B')),8)
        self.assertEqual(self.guard.delay(self.draft(2)),20)
        self.store.db.close()
        self.store=Store(self.path)
        self.guard=SendGuard(self.store, lambda:self.now)
        self.assertEqual(self.guard.delay(self.draft(2)),20)
        self.now+=20
        self.sent(self.draft(2))

    def test_same_content_blocked_but_other_group_allowed_after_cooldown(self):
        self.sent(self.draft(content='hello world'))
        self.now+=20
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(2,content='hello  world'))
        self.sent(self.draft(3,room='B',content='hello world'))
        self.now+=600
        self.sent(self.draft(4,content='hello world'))

    def test_hour_limit_holds_without_scheduling_backlog(self):
        for n in range(20):
            self.sent(self.draft(n))
            self.now+=21
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(21))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM send_attempts').fetchone()[0],20)

    def test_disabled_quotas_survive_restart_but_pacing_and_duplicates_remain(self):
        path=Path(self.temp.name)/'send-policy.json'
        path.write_text(json.dumps({name:None for name in
            ('global_hour_limit','global_day_limit','group_hour_limit','group_day_limit')}),encoding='utf-8')
        self.guard=SendGuard(self.store,lambda:self.now,policy_path=path)
        for n in range(105):
            self.sent(self.draft(n));self.now+=21
        self.guard=SendGuard(self.store,lambda:self.now,policy_path=path)
        self.sent(self.draft(105))
        self.assertEqual(self.guard.delay(self.draft(106)),20)
        self.assertEqual(self.guard.delay(self.draft(106,room='B')),8)
        self.now+=21
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(107,content='reply 105'))
        self.guard.trip('test failure')
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(108))
        self.assertIsNone(self.guard.state()['policy']['global_hour_limit'])

    def test_quota_config_cannot_disable_other_guards(self):
        path=Path(self.temp.name)/'send-policy.json'
        guard=SendGuard(self.store,lambda:self.now,policy_path=path)
        for settings in ({'duplicate_seconds':0},{'global_gap_seconds':-1},{'group_gap_seconds':False},
                         {'global_hour_limit':False},{'global_day_limit':0}):
            path.write_text(json.dumps(settings),encoding='utf-8')
            with self.assertRaises(SendHeld):guard.reserve(self.draft())

    def test_zero_send_gaps_do_not_wait_but_still_deduplicate(self):
        path=Path(self.temp.name)/'send-policy.json'
        path.write_text(json.dumps({'global_gap_seconds':0,'group_gap_seconds':0}),encoding='utf-8')
        self.guard=SendGuard(self.store,lambda:self.now,policy_path=path)
        self.sent(self.draft(1))
        self.assertEqual(self.guard.delay(self.draft(2)),0)
        self.sent(self.draft(2))
        self.assertEqual(self.guard.delay(self.draft(3,room='B')),0)
        self.sent(self.draft(3,room='B'))
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(4,content='reply 1'))
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(2))

    def test_global_day_limit_applies_across_groups(self):
        for n in range(100):
            self.sent(self.draft(n,room='A' if n%2 else 'B'))
            self.now+=700
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(101,room='B'))

    def test_group_daily_limit(self):
        for n in range(60):
            self.sent(self.draft(n))
            self.now+=1000
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(61))

    def test_global_hour_limit(self):
        for n in range(30):
            self.sent(self.draft(n,room='A' if n%2 else 'B'))
            self.now+=30
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(31))

    def test_crash_reservation_blocks_next_send_even_after_restart_and_reset_never_replays(self):
        original=self.draft()
        self.guard.reserve(original)
        self.store.db.close()
        self.store=Store(self.path)
        self.guard=SendGuard(self.store, lambda:self.now)
        self.assertTrue(self.guard.state()['blocked'])
        self.now+=30
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(2))
        self.guard.reset()
        with self.assertRaises(SendHeld):self.guard.reserve(original)
        self.sent(self.draft(2))

    def test_stale_draft_and_clock_rollback_fail_closed(self):
        old=self.draft()
        self.now+=601
        with self.assertRaises(SendHeld):self.guard.reserve(old)
        self.sent(self.draft(2))
        self.now-=100
        with self.assertRaises(SendHeld):self.guard.reserve(self.draft(3))

    def test_two_connections_cannot_reserve_same_request(self):
        # Both guards initialized before either begins sending.
        other=Store(self.path)
        second=SendGuard(other, lambda:self.now)
        barrier=threading.Barrier(2);results=[]
        def run(guard):
            barrier.wait()
            try:guard.reserve(self.draft());results.append('reserved')
            except SendHeld:results.append('held')
        threads=[threading.Thread(target=run,args=(g,)) for g in (self.guard,second)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(3)
        other.db.close()
        self.assertCountEqual(results,['reserved','held'])

    def test_member_flood_and_event_duplicate_gated_before_model(self):
        gate=MentionGate()
        event=dict(source='wechat',room='A',sender='member',id='1',created=self.now,
                   mention_verified=True,is_self=False)
        self.assertEqual(gate.reason(event,self.now),'')
        self.assertEqual(gate.reason(event,self.now),'duplicate_mention')
        self.assertEqual(gate.reason({**event,'id':'2'},self.now),'member_cooldown')
        self.assertEqual(gate.reason({**event,'sender':'another','id':'3'},self.now),'')
        self.assertEqual(gate.reason({**event,'id':'4'},self.now+31),'')
        self.assertEqual(gate.reason({**event,'id':'5'},self.now+601),'stale_mention')


if __name__=='__main__':unittest.main()
