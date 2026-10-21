"""Verify completed automatic replies against authenticated server records."""
import json
from pathlib import Path
import sqlite3
import sys
import time

APP = Path(__file__).resolve().parents[1] / 'app'
sys.path.insert(0, str(APP))
DATA = APP / '.local/quote-m-session'


def verify():
    from session_history import SessionHistory
    from account_scope import AccountHistory
    from lab import Settings
    from m_session_assistant import check_session
    session = json.loads((DATA / 'session.json').read_text(encoding='utf-8'))
    check_session(session)
    base = SessionHistory(DATA)
    registry = json.loads((DATA / 'peer-registry.json').read_text(encoding='utf-8'))['peers']
    by_name = {v['configured_name']: v for v in registry.values()}
    cfg = Settings().get()
    proof = {'group_mention_verified': False, 'any_group_mention_verified': False, 'direct_message_verified': False,
             'at': time.time(), 'automatic_reply_proofs': []}
    path = DATA / 'history.sqlite3'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT o.room,o.event_id,o.content,j.event FROM outbox o JOIN model_jobs j "
                          "ON j.room=o.room AND j.event_id=o.event_id WHERE o.state='sent' AND j.state='sent'").fetchall()
        for row in rows:
            event = json.loads(row['event'])
            if event.get('is_self') or event.get('source') != 'wechat':
                continue
            entry = by_name.get(row['room'])
            if not entry:
                continue
            category = 'group_mention_verified' if entry['kind'] == 'group' else 'direct_message_verified'
            if category == 'group_mention_verified' and event.get('mention_verified') is not True:
                continue
            if category == 'direct_message_verified' and event.get('direct_verified') is not True:
                continue
            reader = AccountHistory(base, entry)
            # Retain verification of real replies sent before the official rename.
            bodies = {name + '\uff1a\n' + row['content'] for name in (cfg['bot_name'], 'Mydex')}
            for shard in reader.message_paths():
                for response in reader.fetch(shard, reader.name)['events']:
                    if (response.get('is_self') and response['content'] in bodies and response['id'].isdigit()
                            and int(response['id']) > 0 and response['created'] >= event['created']):
                        if category == 'group_mention_verified':
                            proof['any_group_mention_verified'] = True
                            if entry['peer'] == base.room:
                                proof[category] = True
                        else:
                            proof[category] = True
                        proof['automatic_reply_proofs'].append({'kind': entry['kind'],
                              'request_server_id': row['event_id'], 'reply_server_id': response['id'],
                              'peer': entry['peer'], 'server_record_verified': True})
                        break
        states = dict(db.execute('SELECT state,COUNT(*) FROM model_jobs GROUP BY state').fetchall())
    target = DATA / 'live-validation.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(proof, indent=2), encoding='utf-8')
    temporary.replace(target)
    state = json.loads((DATA / 'assistant-status.json').read_text(encoding='utf-8'))
    print(json.dumps({'group_mention_verified': proof['group_mention_verified'],
                      'any_group_mention_verified': proof['any_group_mention_verified'],
                      'direct_message_verified': proof['direct_message_verified'], 'job_states': states,
                      'runtime_phase': state['phase'], 'status_age_seconds': round(time.time() - state['at'], 1),
                      'model_busy': any(g.get('model_busy') for g in state.get('groups', [])),
                      'inbox_error_types': [g['last_error'] for g in state.get('groups', []) if g.get('last_error')],
                      'sender_blocked': state.get('sender', {}).get('send_guard', {}).get('blocked')}))


if __name__ == '__main__':
    verify()
