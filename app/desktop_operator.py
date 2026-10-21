"""Durable, account-bound inbox for this desktop Codex conversation."""
from contextlib import closing, contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import time

from lab import UserError

PENDING_MAX_AGE_SECONDS = 30 * 60


class DesktopBridge:
    def __init__(self, data):
        self.data = Path(data)
        self.path = self.data / 'desktop-operator.sqlite3'
        with self.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS requests(
                id TEXT PRIMARY KEY,event_id TEXT NOT NULL,room TEXT NOT NULL,
                sender TEXT NOT NULL,account TEXT NOT NULL,content TEXT NOT NULL,
                kind TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL,
                claimed REAL,result TEXT NOT NULL DEFAULT '',draft_id TEXT,
                proof TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '')''')

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.path, timeout=15)) as db, db:
            db.row_factory = sqlite3.Row
            yield db

    def config(self):
        path = self.data / 'desktop-operator.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None

    def selected(self, entry, account):
        cfg = self.config()
        if not cfg or entry.get('kind') != 'direct' or entry.get('peer') != cfg.get('sender_account'):
            return False
        authority = json.loads((self.data / 'operator-authority.json').read_text(encoding='utf-8'))
        session = json.loads((self.data / 'session.json').read_text(encoding='utf-8'))
        if (cfg.get('enabled') is not True or cfg.get('receiving_account') != account
                or cfg.get('pid') != session.get('pid') or cfg.get('process_created') != session.get('created')
                or authority.get('sender_account') != entry['peer']
                or authority.get('receiving_account') != account
                or authority.get('authority_level') != 'same_user_instruction_authority_as_owner'
                or entry.get('authenticated_table') != 'Msg_' + hashlib.md5(entry['peer'].encode()).hexdigest()):
            raise UserError('当前窗口的管理私聊绑定需要重新核验')
        return True

    def capture(self, event, entry, account):
        if not self.selected(entry, account):
            return False
        cfg = self.config()
        event_id = str(event.get('id', ''))
        if (event.get('source') != 'wechat' or event.get('is_self')
                or event.get('sender') != entry['peer'] or event.get('room') != entry['configured_name']
                or not event_id.isdecimal() or int(event_id) == 0
                or event.get('created', 0) < cfg['activated_at']
                or not -5 <= time.time() - event.get('created', 0) <= 600):
            return True  # This selected peer must never fall through to Qwen.
        task_id = hashlib.sha256((account + '\0' + entry['peer'] + '\0' + event_id).encode()).hexdigest()
        with self.db() as db:
            db.execute('''INSERT OR IGNORE INTO requests
                (id,event_id,room,sender,account,content,kind,created,state)
                VALUES(?,?,?,?,?,?,?,?,?)''', (task_id, event_id, entry['configured_name'],
                entry['peer'], account, event['content'], event.get('type', 'text'), event['created'], 'pending'))
        return True

    def pending(self):
        with self.db() as db:
            db.execute("UPDATE requests SET state='expired' WHERE state='pending' AND created<?", (time.time()-PENDING_MAX_AGE_SECONDS,))
            rows = db.execute("SELECT id,content,kind,created,state FROM requests WHERE state IN ('pending','claimed','ready','sending','needs_review') ORDER BY created,id LIMIT 20").fetchall()
            return [dict(r) for r in rows]

    def start_run(self):
        # A service restart must not replay a previously queued instruction or reply.
        with self.db() as db:
            db.execute("UPDATE requests SET state='expired' WHERE state='pending'")
            db.execute("UPDATE requests SET state='needs_review',error='assistant_restarted' WHERE state IN ('claimed','ready','sending')")

    def claim(self, task_id):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM requests WHERE state IN ('claimed','ready','sending','needs_review') LIMIT 1").fetchone():
                raise UserError('已有任务处理中或待核对，不自动重复执行')
            row = db.execute("SELECT * FROM requests WHERE state='pending' ORDER BY created,id LIMIT 1").fetchone()
            if not row or row['id'] != task_id or time.time()-row['created'] > PENDING_MAX_AGE_SECONDS:
                raise UserError('只能领取最新窗口内的队首任务')
            db.execute("UPDATE requests SET state='claimed',claimed=? WHERE id=?", (time.time(), task_id))
            return {'id': row['id'], 'content': row['content'], 'kind': row['kind'], 'created': row['created']}

    def complete(self, task_id, result, store, bot_name):
        if not isinstance(result, str) or not result.strip() or len((bot_name+'：\n'+result).encode('utf-8')) > 3000 or '\0' in result:
            raise UserError('微信任务回执需要非空短文字，且不超过单条发送长度')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM requests WHERE id=?', (task_id,)).fetchone()
            if not row or row['state'] != 'claimed':
                raise UserError('任务未领取或已有回执，禁止重复提交')
            with store.lock:
                prior = store.db.execute("SELECT * FROM outbox WHERE source='wechat' AND room=? AND event_id=?", (row['room'],row['event_id'])).fetchone()
                if prior:
                    # An earlier crash may have left a draft before the bridge commit.
                    db.execute("UPDATE requests SET state='needs_review',error='existing_draft' WHERE id=?", (task_id,))
                    return {'state': 'needs_review'}
            store.add('wechat', row['room'], bot_name, result, 'assistant', row['event_id'])
            draft_id = store.draft(row['room'], result, 'wechat', row['event_id'])
            db.execute("UPDATE requests SET state='ready',result=?,draft_id=? WHERE id=?", (result, draft_id, task_id))
        return {'state': 'ready'}

    def deliver_one(self, entry, account, sender):
        if not self.selected(entry, account):
            return
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT * FROM requests WHERE state='ready' AND sender=? AND account=? ORDER BY created,id LIMIT 1", (entry['peer'],account)).fetchone()
            if not row:
                return
            db.execute("UPDATE requests SET state='sending' WHERE id=?", (row['id'],))
        try:
            outcome = sender.send_draft(row['draft_id'])
            verified = outcome.get('status') == 'sent' and outcome.get('server_record_verified') is True
            with self.db() as db:
                db.execute('UPDATE requests SET state=?,proof=? WHERE id=?',
                           ('sent' if verified else 'needs_review', json.dumps(outcome), row['id']))
        except Exception as exc:
            with self.db() as db:
                db.execute("UPDATE requests SET state='needs_review',error=? WHERE id=?", (type(exc).__name__,row['id']))

    def status(self, task_id=None):
        with self.db() as db:
            if task_id:
                row = db.execute('SELECT state,proof,error FROM requests WHERE id=?', (task_id,)).fetchone()
                if not row:
                    raise UserError('Unknown task')
                return {'state': row['state'], 'server_record_verified': bool(json.loads(row['proof'] or '{}').get('server_record_verified')), 'error': row['error']}
            return {row[0]: row[1] for row in db.execute('SELECT state,COUNT(*) FROM requests GROUP BY state')}
