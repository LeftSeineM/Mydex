from unittest.mock import patch
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from lab import Settings, Store, Engine, UserError
from group_participation import HACKATHON_ROOM, ParticipationSettings, load_policy
from account_assistant import AccountInbox, AccountSender


class ParticipationTests(unittest.TestCase):
    def setUp(self):
        # Isolate policy and clock from the original machine's private state.
        for target, value in [('account_assistant.load_scope', {'all_direct_messages': False}), ('account_assistant.replies_allowed', True)]:
            guard = patch(target, return_value=value)
            guard.start()
            self.addCleanup(guard.stop)
        self.reply_window = patch('account_assistant.replies_allowed',return_value=True)
        self.reply_window.start()
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.settings=Settings(self.root/'settings.json')
        self.store=Store(self.root/'history.db')
        self.policy={'enabled':True,'minimum_ordinary_messages':10}
        self.inbox=self.make_inbox('group-one')

    def tearDown(self):
        self.reply_window.stop()
        self.store.db.close()
        self.temp.cleanup()

    def make_inbox(self,room,kind='group'):
        entry={'kind':kind,'peer':room,'configured_name':room,'group_model_authorized':True,
               'registered_since':0,'runtime_started':time.time()-1}
        cfg=ParticipationSettings(self.settings,entry,self.policy)
        engine=Engine(cfg,self.store,data=self.root)
        reader=Mock()
        reader.message_paths.return_value=['test.db']
        return AccountInbox(engine,self.root,entry=entry,scope=room,reader_factory=lambda:reader)

    def event(self,n,room='group-one',**changes):
        return {'source':'wechat','id':str(n),'room':room,'sender':'member','type':'text',
                'content':'这个问题怎么看？','created':time.time(),'is_self':False,**changes}

    def feed(self,start,stop,inbox=None,**changes):
        inbox=inbox or self.inbox
        for n in range(start,stop+1):inbox.consider_event(self.event(n,**{'room':inbox.room,**changes}))

    def jobs(self,room='group-one'):
        return self.store.db.execute('SELECT * FROM model_jobs WHERE room=? ORDER BY ready,event_id',(room,)).fetchall()

    def test_first_nine_never_trigger_tenth_can_trigger(self):
        self.feed(1,9)
        self.assertEqual(len(self.jobs()),0)
        self.feed(10,10)
        self.assertEqual(len(self.jobs()),1)
        event=json.loads(self.jobs()[0]['event'])
        self.assertTrue(event['conversation_verified'])
        self.assertFalse(event.get('mention_verified',False))

    def test_duplicate_events_do_not_increase_allowance(self):
        for _ in range(20):self.inbox.consider_event(self.event(1))
        self.feed(2,9)
        self.assertEqual(len(self.jobs()),0)
        self.feed(10,10)
        self.assertEqual(len(self.jobs()),1)

    def test_tenth_message_does_not_force_meaningless_interruption(self):
        self.feed(1,10,content='哈哈')
        self.assertEqual(len(self.jobs()),0)
        self.feed(11,11)
        self.assertEqual(len(self.jobs()),1)

    def test_delivery_requires_ten_fresh_messages_not_bank_of_old_allowances(self):
        self.feed(1,10)
        self.feed(11,45)
        self.assertEqual(len(self.jobs()),1)
        self.inbox.set_job('10','sent')
        self.feed(46,54)
        self.assertEqual(len(self.jobs()),1)
        self.feed(55,55)
        self.assertEqual(len(self.jobs()),2)

    def test_real_mentions_bypass_ordinary_gate_and_do_not_count(self):
        self.feed(1,3,mention_verified=True)
        self.assertEqual(len(self.jobs()),3)
        self.feed(4,12)
        self.assertEqual(len(self.jobs()),3)
        self.feed(13,13)
        self.assertEqual(len(self.jobs()),4)

    def test_self_system_old_wrong_room_and_simulation_do_not_count(self):
        for change in ({'is_self':True},{'type':'system'},{'created':time.time()-1000},
                       {'room':'other'},{'source':'simulation'}):
            self.feed(1,20,**change)
        self.assertEqual(len(self.jobs()),0)
        self.feed(21,29)
        self.assertEqual(len(self.jobs()),0)

    def test_each_group_has_independent_counter(self):
        other=self.make_inbox('group-two')
        self.feed(1,9)
        self.feed(1,1,inbox=other)
        self.assertEqual(len(self.jobs()),0)
        self.assertEqual(len(self.jobs('group-two')),0)
        self.feed(10,10)
        self.assertEqual(len(self.jobs()),1)
        self.assertEqual(len(self.jobs('group-two')),0)

    def test_restart_preserves_counts_and_never_replays_old_queued_replies(self):
        self.feed(1,9)
        self.inbox=self.make_inbox('group-one')
        self.feed(10,10)
        self.assertEqual(len(self.jobs()),1)
        self.inbox=self.make_inbox('group-one')
        self.assertEqual(self.jobs()[0]['state'],'expired')
        self.feed(11,19)
        self.assertEqual(len(self.jobs()),1)
        self.feed(20,20)
        self.assertEqual(len(self.jobs()),2)

    def test_direct_messages_remain_disabled(self):
        dm=self.make_inbox('member','direct')
        dm.consider_event(self.event(1,room='member'))
        self.assertEqual(len(self.jobs('member')),0)
        self.assertFalse(dm.engine.settings.get()['conversation_enabled'])
        self.assertFalse(self.settings.get()['conversation_enabled'])

    def resume_inbox(self):
        self.inbox.checkpoint.write_text(json.dumps({
            'room':self.inbox.room,'cursors':{'test.db':8}}),encoding='utf-8')
        return self.make_inbox('group-one')

    def test_restart_accepts_recent_unread_mentions_from_saved_cursor(self):
        self.policy['enabled']=False
        self.inbox=self.resume_inbox()
        event=self.event(10,created=time.time()-30,mention_verified=True)
        self.inbox.consider_event(event)
        self.inbox.consider_event(event)
        self.assertEqual(len(self.jobs()),1)
        self.assertEqual(self.jobs()[0]['state'],'pending')

    def test_restart_still_rejects_stale_messages_and_unmentioned_chat(self):
        self.policy['enabled']=False
        self.inbox=self.resume_inbox()
        self.inbox.consider_event(self.event(10,created=time.time()-601,mention_verified=True))
        self.inbox.consider_event(self.event(11,created=time.time()-30))
        self.assertEqual(len(self.jobs()),0)

    def test_first_start_does_not_replay_preexisting_mentions(self):
        self.inbox.consider_event(self.event(10,created=time.time()-30,mention_verified=True))
        self.assertEqual(len(self.jobs()),0)

    def test_restart_does_not_accept_messages_before_group_registration(self):
        self.policy['enabled']=False
        self.inbox=self.resume_inbox()
        self.inbox.entry['registered_since']=time.time()-10
        self.inbox.consider_event(self.event(10,created=time.time()-30,mention_verified=True))
        self.assertEqual(len(self.jobs()),0)

    def test_policy_validation_rejects_relaxed_or_malformed_thresholds(self):
        self.assertFalse(load_policy(self.root)['enabled'])
        for count in (0,1,9,True,'10'):
            (self.root/'group-participation.json').write_text(json.dumps({'enabled':True,'minimum_ordinary_messages':count}),encoding='utf-8')
            with self.assertRaises(UserError):load_policy(self.root)

    def test_disabled_policy_keeps_mentions_only(self):
        self.policy['enabled']=False
        self.feed(1,30)
        self.assertEqual(len(self.jobs()),0)
        self.feed(31,31,mention_verified=True)
        self.assertEqual(len(self.jobs()),1)

    def test_hackathon_identity_and_mission_are_group_specific(self):
        self.policy['enabled']=False
        hackathon=self.make_inbox(HACKATHON_ROOM)
        cfg=hackathon.engine.settings.get()
        self.assertEqual(cfg['bot_name'],'EE黑客松·官方小bot')
        self.assertIn('EE 黑客松的组队与互动',cfg['system_prompt'])
        self.assertIn('EE黑客松·官方小bot',cfg['visible_mention_aliases'])
        self.assertIn('不要自称“AI毛开逸”',cfg['system_prompt'])
        self.assertFalse(cfg['conversation_enabled'])
        self.assertNotEqual(self.inbox.engine.settings.get()['bot_name'],'EE黑客松·官方小bot')
        self.assertNotIn('EE 黑客松的组队与互动',self.inbox.engine.settings.get()['system_prompt'])

    def test_hackathon_native_sender_uses_group_display_name(self):
        sender=object.__new__(AccountSender)
        sender.engine=self.inbox.engine
        sender.registry={
            HACKATHON_ROOM:{'peer':HACKATHON_ROOM,'kind':'group','configured_name':'hackathon'},
            'other@chatroom':{'peer':'other@chatroom','kind':'group','configured_name':'other'}}
        self.assertEqual(sender.display_name('hackathon'),'EE黑客松·官方小bot')
        self.assertEqual(sender.display_name('other'),self.settings.get()['bot_name'])

    def test_paused_hackathon_never_queues_a_mention(self):
        self.policy['paused_rooms']=[HACKATHON_ROOM]
        hackathon=self.make_inbox(HACKATHON_ROOM)
        self.assertFalse(hackathon.engine.settings.get()['group_model_authorized'])
        hackathon.consider_event(self.event(1,room=HACKATHON_ROOM,mention_verified=True))
        self.assertEqual(len(self.jobs(HACKATHON_ROOM)),0)
        self.assertFalse(self.inbox.engine.settings.get()['replies_paused'])


if __name__=='__main__':unittest.main()
