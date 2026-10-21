"""Separate group memories over one local model configuration."""
import json
from lab import DATA,UserError
ALLOWED_ROOMS=frozenset({'90000000003@chatroom','90000000008@chatroom','90000000001@chatroom','90000000005@chatroom','90000000002@chatroom','90000000004@chatroom','90000000007@chatroom'})

def scopes(settings,data=DATA):
    try:
        groups=json.loads((data/'monitored-groups.json').read_text(encoding='utf-8'))
        if not isinstance(groups,list) or not 1<=len(groups)<=len(ALLOWED_ROOMS):raise ValueError('Invalid scopes')
        if any(g['room_id'] not in ALLOWED_ROOMS for g in groups):raise ValueError('Unsupported groups')
        if len({g['room_id'] for g in groups})!=len(groups) or len({g['configured_name'] for g in groups})!=len(groups):
            raise ValueError('Duplicate group identity')
        return groups
    except FileNotFoundError:
        return [{'configured_name':settings.get()['group'],'name':settings.get()['group'],'room_id':'90000000003@chatroom'}]

class GroupSettings:
    def __init__(self,settings,entry):self.settings=settings;self.entry=entry
    def get(self,public=False):
        cfg=self.settings.get(public)
        cfg['group']=self.entry['configured_name']
        cfg['group_model_authorized']=bool(cfg['group_model_authorized'] and self.entry.get('group_model_authorized',False))
        if self.entry.get('kind')=='direct':
            cfg['system_prompt']+='\n本次是一对一微信私聊，直接回答对方。只使用本会话提供的记录，不提及或披露其他群和私聊内容。图片、语音、附件只有占位信息时，说明无法读取正文，不猜测内容。'
        return cfg
