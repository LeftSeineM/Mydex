import json
from pathlib import Path
import tempfile
import time
import unittest
from lab import Engine,Settings,Store
from group_scopes import GroupSettings,scopes

class Backend:
    def __init__(self):self.inputs=[]
    def reply(self,cfg,messages):self.inputs.append(messages);return '收到'

class Tests(unittest.TestCase):
    def test_two_groups_have_separate_model_context_and_linked_drafts(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);settings=Settings(root/'settings.json');settings.update({'group_model_authorized':True})
            entries=[{'configured_name':'一群','name':'一群','room_id':'90000000003@chatroom','group_model_authorized':True},
                     {'configured_name':'二群','name':'二群','room_id':'90000000008@chatroom','group_model_authorized':True}]
            (root/'monitored-groups.json').write_text(json.dumps(entries),encoding='utf-8')
            store=Store(root/'records.db');backend=Backend()
            try:
                engines=[Engine(GroupSettings(settings,e),store,backend) for e in scopes(settings,root)]
                engines[0].process({'source':'wechat','room':'一群','sender':'A','id':'1','created':time.time(),
                                    'content':'一群项目机密'})
                result=engines[1].process({'source':'wechat','room':'二群','sender':'B','id':'2','created':time.time(),
                                          'content':'@账号 问题','mention_verified':True})
                self.assertNotIn('一群项目机密',json.dumps(backend.inputs[-1],ensure_ascii=False))
                draft=store.pending()[0]
                self.assertEqual((draft['room'],draft['source'],draft['event_id']),('二群','wechat','2'))
                self.assertEqual(draft['id'],result['draft_id'])
            finally:store.db.close()

if __name__=='__main__':unittest.main()
