"""Opt-in, per-group ordinary participation; direct messages keep their route."""
import json
from pathlib import Path

from group_scopes import GroupSettings
from lab import UserError

HACKATHON_ROOM = '90000000006@chatroom'


def load_policy(data):
    path = Path(data) / 'group-participation.json'
    if not path.exists():
        return {'enabled': False, 'minimum_ordinary_messages': 10,
                'always_reply_rooms': [], 'visible_mention_aliases': {}}
    policy = json.loads(path.read_text(encoding='utf-8'))
    count = policy.get('minimum_ordinary_messages')
    rooms = policy.get('always_reply_rooms', [])
    paused = policy.get('paused_rooms', [])
    aliases = policy.get('visible_mention_aliases', {})
    if (type(policy.get('enabled')) is not bool or type(count) is not int or count < 10
            or not isinstance(rooms, list) or len(rooms) > 8
            or not isinstance(paused, list)
            or any(not isinstance(room, str) or not room.endswith('@chatroom') for room in paused)
            or len(set(paused)) != len(paused)
            or any(not isinstance(room, str) or not room.endswith('@chatroom') for room in rooms)
            or len(set(rooms)) != len(rooms)
            or not isinstance(aliases, dict) or len(aliases) > 8
            or any(not isinstance(room, str) or not room.endswith('@chatroom')
                   or not isinstance(names, list) or not 1 <= len(names) <= 4
                   or any(not isinstance(name, str) or not 1 <= len(name) <= 32 for name in names)
                   or len(set(names)) != len(names) for room, names in aliases.items())):
        raise UserError('群聊主动参与策略需要布尔开关和至少10条消息的间隔')
    policy['always_reply_rooms'] = rooms
    policy['paused_rooms'] = paused
    policy['visible_mention_aliases'] = aliases
    return policy


class ParticipationSettings(GroupSettings):
    def __init__(self, settings, entry, policy):
        super().__init__(settings, entry)
        self.policy = policy

    def get(self, public=False):
        cfg = super().get(public)
        paused = self.entry.get('kind') == 'group' and self.entry.get('peer') in self.policy.get('paused_rooms', [])
        cfg['replies_paused'] = paused
        if paused:
            cfg['group_model_authorized'] = False
        cfg['visible_mention_aliases'] = self.policy.get('visible_mention_aliases', {}).get(
            self.entry.get('peer'), [])
        if self.entry.get('kind') == 'group' and self.entry.get('peer') == HACKATHON_ROOM:
            cfg['bot_name'] = 'EE黑客松·官方小bot'
            cfg['visible_mention_aliases'] = list(dict.fromkeys(
                [*cfg['visible_mention_aliases'], 'EE黑客松·官方小bot']))
            cfg['system_prompt'] += (
                '\n本群专属身份与任务：你在本群的微信备注名是“EE黑客松·官方小bot”，'
                '是协助群友的 AI 助手，不是毛开逸本人。不要自称“AI毛开逸”，'
                '也不要把该称呼当成自己的署名；被问到身份时按本群备注名介绍自己。'
                '本群核心任务是支持 EE 黑客松的组队与互动：帮助成员表达项目方向、技能与需求，'
                '寻找互补的队友，梳理合作问题并促进有实质内容的交流。'
                '只依据当前群提供的记录描述成员、队伍和进展；未知就说明未知，不猜测关系或意图。'
                '保持简洁自然，仅在本群允许的消息触发时回复。'
                '本群专属称呼覆盖前文通用的 Mydex 自我介绍规则。')
        always = (self.entry.get('kind') == 'group'
                  and self.entry.get('peer') in self.policy.get('always_reply_rooms', []))
        if always:
            cfg['conversation_enabled'] = True
            cfg['conversation_min_messages'] = 0
            cfg['conversation_reply_all'] = True
            cfg['system_prompt'] += '\n本群已由群主授权持续回复：对每条新文字或引用自然回应，承接上下文，避免机械复述；不要回复自己的消息。'
        elif self.entry.get('kind') == 'group' and self.policy['enabled']:
            cfg['conversation_enabled'] = True
            cfg['conversation_min_messages'] = self.policy['minimum_ordinary_messages']
            cfg['system_prompt'] += '\n群聊普通消息允许偶尔参与：只在有实质内容可补充时简短回应，不刷屏、不复读、不主动追问。参与频率由宿主按群独立限制。'
        return cfg
