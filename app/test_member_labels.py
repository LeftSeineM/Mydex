import json
from pathlib import Path
import tempfile
import time
import unittest
from lab import Engine,Settings,Store
from member_labels import display_sender,prettify_reply,group_nicknames
class Tests(unittest.TestCase):
    def test_labels_are_group_scoped_and_unknown_ids_are_not_echoed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'member-labels.json').write_text(json.dumps({'groups':[
                {'aliases':['A'],'labels':{'wxid_one':'一群昵称'}},
                {'aliases':['B'],'labels':{'wxid_one':'二群昵称'}}]}),encoding='utf-8')
            self.assertEqual(display_sender('wxid_one','A',root),'一群昵称')
            self.assertEqual(display_sender('wxid_one','B',root),'二群昵称')
            self.assertEqual(prettify_reply('@wxid_one 已说；wxid_unknown 未提供','A',root),'一群昵称 已说；一位群友 未提供')
    def test_group_display_name_field_is_parsed_without_inviter_identity(self):
        user=b'wxid_one';nickname='群昵称'.encode();inviter=b'wxid_inviter'
        record=b'\x0a'+bytes([len(user)])+user+b'\x12'+bytes([len(nickname)])+nickname+b'\x22'+bytes([len(inviter)])+inviter
        blob=b'\x0a'+bytes([len(record)])+record
        self.assertEqual(group_nicknames(blob),{'wxid_one':'群昵称'})
    def test_recall_finds_old_topic_and_excludes_other_group_and_bot_echoes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);settings=Settings(root/'settings.json');store=Store(root/'db.sqlite')
            try:
                store.add('wechat','AI助手测试群','A','学习方法：先做练习再看答案','user','old',1700000000)
                store.add('wechat','别的群','B','学习方法：别的群的秘密','user','secret',1700000010)
                store.add('wechat','AI助手测试群','Mydex','Mydex：我能解释学习方法','user','bot',time.time())
                for i in range(100):store.add('wechat','AI助手测试群','A','今天闲聊'+str(i),'user','new'+str(i),time.time()+i)
                rows=store.recall('wechat','AI助手测试群','@账号 之前聊过哪些学习方法？')
                self.assertEqual([r['event_id'] for r in rows],['old'])
            finally:store.db.close()
if __name__=='__main__':unittest.main()
