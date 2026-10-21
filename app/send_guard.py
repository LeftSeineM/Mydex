"""Persistent anti-spam limits, not an anti-detection or account-safety claim.

Reservations precede native calls. Unknown outcomes consume budget and cannot
be replayed, including after restart. No message bodies are stored here.
"""
import hashlib
import json
from pathlib import Path
import time

from lab import UserError


POLICY = {
    'global_gap_seconds': 8,
    'group_gap_seconds': 20,
    'group_hour_limit': 20,
    'group_day_limit': 60,
    'global_hour_limit': 30,
    'global_day_limit': 100,
    'duplicate_seconds': 600,
    'max_draft_age_seconds': 600,
    'max_pending_mentions': 8,
    'member_cooldown_seconds': 30,
}


class SendHeld(UserError):
    """Keep the answer locally; do not schedule an automatic retry."""


class SendGuard:
    def __init__(self, store, clock=time.time, policy_path=None):
        self.store, self.clock = store, clock
        self.policy_path = Path(policy_path) if policy_path is not None else None
        with store.lock, store.db:
            store.db.executescript('''
                CREATE TABLE IF NOT EXISTS send_attempts (
                    draft_id TEXT PRIMARY KEY, room TEXT NOT NULL,
                    event_id TEXT NOT NULL, digest TEXT NOT NULL,
                    attempted REAL NOT NULL, outcome TEXT NOT NULL,
                    UNIQUE(room,event_id));
                CREATE INDEX IF NOT EXISTS send_attempts_time ON send_attempts(attempted);
                CREATE TABLE IF NOT EXISTS send_circuit (
                    id INTEGER PRIMARY KEY CHECK(id=1), reason TEXT NOT NULL,
                    changed REAL NOT NULL);
            ''')
            # Account for recent sends made by the previous version too.
            rows = store.db.execute("SELECT * FROM outbox WHERE source='wechat' "
                                    "AND state IN ('sent','sending','unknown') AND created>?",
                                    (clock()-86400,)).fetchall()
            for row in rows:
                store.db.execute('INSERT OR IGNORE INTO send_attempts VALUES(?,?,?,?,?,?)',
                                 (row['id'], row['room'], row['event_id'] or row['id'],
                                  self.digest(row['content']), row['created'], row['state']))
            uncertain = store.db.execute("SELECT 1 FROM send_attempts WHERE outcome IN ('reserved','sending','unknown') LIMIT 1").fetchone()
            if uncertain:
                store.db.execute("UPDATE send_attempts SET outcome='unknown' WHERE outcome IN ('reserved','sending')")
                store.db.execute('INSERT OR IGNORE INTO send_circuit VALUES(1,?,?)',
                                 ('上次发送结果不明；请核对群记录后手动恢复', clock()))

    @staticmethod
    def digest(content):
        return hashlib.sha256(' '.join(content.split()).encode('utf-8')).hexdigest()

    def policy(self):
        policy = dict(POLICY)
        if self.policy_path is not None and self.policy_path.exists():
            quotas = json.loads(self.policy_path.read_text(encoding='utf-8'))
            limits = {'global_hour_limit', 'global_day_limit', 'group_hour_limit', 'group_day_limit'}
            gaps = {'global_gap_seconds', 'group_gap_seconds'}
            allowed = limits | gaps
            if not isinstance(quotas, dict) or set(quotas)-allowed:
                raise SendHeld('发送配置无效；未修改重复检查和失败保护')
            for name, value in quotas.items():
                if name in gaps and (type(value) is not int or value < 0):
                    raise SendHeld('发送间隔必须为非负整数秒，0 表示不额外等待')
                if name in limits and value is not None and (type(value) is not int or value < 1):
                    raise SendHeld('条数上限必须为正整数，或用 null 表示不限制条数')
            policy.update(quotas)
        return policy

    def state(self):
        with self.store.lock:
            row = self.store.db.execute('SELECT reason,changed FROM send_circuit WHERE id=1').fetchone()
        return {'blocked': bool(row), 'reason': row['reason'] if row else '',
                'policy': self.policy()}

    def trip(self, reason):
        with self.store.lock, self.store.db:
            self.store.db.execute('INSERT OR REPLACE INTO send_circuit VALUES(1,?,?)',
                                  (reason, self.clock()))

    def reset(self):
        # Called only by an explicit local enable action, never by the guardian.
        with self.store.lock, self.store.db:
            self.store.db.execute('DELETE FROM send_circuit')

    def _check(self, draft):
        now = self.clock()
        policy = self.policy()
        row = self.store.db.execute('SELECT reason FROM send_circuit WHERE id=1').fetchone()
        if row:
            raise SendHeld('自动发送已保护性暂停：'+row['reason'])
        if not -5 <= now-draft['created'] <= POLICY['max_draft_age_seconds']:
            raise SendHeld('回复已过期或时间异常；仅保留本地草稿')
        rows = self.store.db.execute('SELECT * FROM send_attempts WHERE attempted>?', (now-86400,)).fetchall()
        if any(r['attempted'] > now+5 for r in rows):
            raise SendHeld('系统时间回退；自动发送暂停，等待时钟恢复')
        if self.store.db.execute('SELECT 1 FROM send_attempts WHERE draft_id=? OR (room=? AND event_id=?)',
                                 (draft['id'], draft['room'], draft['event_id'])).fetchone():
            raise SendHeld('本次提问已有发送尝试；不会重复发送')
        group = [r for r in rows if r['room'] == draft['room']]
        digest = self.digest(draft['content'])
        if any(r['digest'] == digest and r['attempted'] > now-POLICY['duplicate_seconds'] for r in group):
            raise SendHeld('本群近期已有相同回复；已拦截重复内容')
        for subset, hours, limit in ((rows,1,policy['global_hour_limit']),
                                      (rows,24,policy['global_day_limit']),
                                      (group,1,policy['group_hour_limit']),
                                      (group,24,policy['group_day_limit'])):
            if limit is not None and sum(r['attempted'] > now-hours*3600 for r in subset) >= limit:
                raise SendHeld('已达到本机设置的发送上限；仅保留草稿，不自动补发')
        last = max((r['attempted'] for r in rows), default=0)
        group_last = max((r['attempted'] for r in group), default=0)
        return max(0, last+policy['global_gap_seconds']-now,
                   group_last+policy['group_gap_seconds']-now)

    def delay(self, draft):
        with self.store.lock:
            return self._check(draft)

    def reserve(self, draft):
        # BEGIN IMMEDIATE also serializes independent processes sharing the DB.
        with self.store.lock, self.store.db:
            self.store.db.execute('BEGIN IMMEDIATE')
            if self._check(draft) > 0:
                raise SendHeld('发送冷却尚未结束；本条保留为草稿')
            self.store.db.execute('INSERT INTO send_attempts VALUES(?,?,?,?,?,?)',
                                 (draft['id'], draft['room'], draft['event_id'],
                                  self.digest(draft['content']), self.clock(), 'reserved'))

    def finish(self, key, outcome):
        with self.store.lock, self.store.db:
            self.store.db.execute('UPDATE send_attempts SET outcome=? WHERE draft_id=?', (outcome,key))


class MentionGate:
    """Bound model work at ingestion, without dropping ordinary history."""
    def __init__(self):
        self.seen = {}
        self.members = {}

    def reason(self, event, now=None):
        now = time.time() if now is None else now
        created = event.get('created', 0)
        if not -5 <= now-created <= POLICY['max_draft_age_seconds']:
            return 'stale_mention'
        explicit_test = event.get('is_self') is True and event.get('self_command_verified') is True
        if event.get('source') != 'wechat' or not (explicit_test or (
                event.get('is_self') is not True and event.get('mention_verified') is True)):
            return 'not_incoming_mention'
        self.seen = {k:v for k,v in self.seen.items() if v > now-86400}
        self.members = {k:v for k,v in self.members.items() if v > now-POLICY['member_cooldown_seconds']}
        key = (event['room'], event['id'])
        if key in self.seen:
            return 'duplicate_mention'
        member = (event['room'], event['sender'])
        if member in self.members:
            return 'member_cooldown'
        self.seen[key] = now
        self.members[member] = now
        return ''
