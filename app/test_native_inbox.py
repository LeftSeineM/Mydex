import json
from pathlib import Path
import tempfile
import unittest
from lab import Engine,Settings,Store
from native_inbox import NativeInbox,verified_mention
class Backend:
    calls=0
    def reply(self,cfg,messages):self.calls+=1;return '群聊摘要'
class InboxTests(unittest.TestCase):
    def test_real_at_metadata_and_malformed_xml(self):
        self.assertTrue(verified_mention('<msgsource><atuserlist><![CDATA[wxid_bot,wxid_other]]></atuserlist></msgsource>','wxid_bot'))
        self.assertFalse(verified_mention('<msgsource><atuserlist>wxid_bot2</atuserlist></msgsource>','wxid_bot'))
        self.assertFalse(verified_mention('<!DOCTYPE x><x/>','wxid_bot'))
        self.assertFalse(verified_mention('broken','wxid_bot'))
    def test_backlog_archives_without_replaying_and_new_at_creates_draft(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);settings=Settings(root/'settings.json');settings.update({'group':'指定群'})
            store=Store(root/'history.db');backend=Backend();engine=Engine(settings,store,backend)
            inbox=NativeInbox(engine,root)
            (root/'outbound-sample-evidence.json').write_text(json.dumps({'group_name':'指定群','room_id_candidate':'123@chatroom'}),encoding='utf-8')
            def event(identity,content):
                return {'id':identity,'room_id':'123@chatroom','sender_id':'wxid_M','receiver_id':'wxid_bot',
                        'content':content,'created':1700000000+int(identity),'type':'text',
                        'msg_source':'<msgsource><atuserlist>wxid_bot</atuserlist></msgsource>'}
            inbox.path.write_text(json.dumps(event('1','@账户实际昵称 旧问题'))+'\n',encoding='utf-8')
            try:
                inbox.consume(True)
                self.assertEqual(backend.calls,0)
                with inbox.path.open('a',encoding='utf-8') as stream:stream.write(json.dumps(event('2','@账户实际昵称 总结群聊'))+'\n')
                inbox.consume()
                self.assertEqual(backend.calls,1)
                self.assertEqual(len(store.pending()),1)
                inbox.consume();self.assertEqual(backend.calls,1)
                wrong=event('3','wrong');wrong['room_id']='other@chatroom'
                with self.assertRaises(Exception):inbox.event(wrong)
            finally:store.db.close()
if __name__=='__main__':unittest.main()
