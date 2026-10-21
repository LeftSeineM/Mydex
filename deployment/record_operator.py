"""Record an explicit owner delegation; this does not implement remote commands."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

APP = Path(__file__).resolve().parents[1] / 'app'
sys.path.insert(0, str(APP))
DATA = APP / '.local/quote-m-session'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-owner-delegation', action='store_true', required=True)
    parser.parse_args()
    from m_session_assistant import check_session
    from session_history import SessionHistory
    from history_reader import HistoryView
    session = json.loads((DATA / 'session.json').read_text(encoding='utf-8'))
    check_session(session)
    base = SessionHistory(DATA)
    contacts = [p for p in base.keys if Path(p).name == 'contact.db']
    if len(contacts) != 1:
        raise ValueError('One authenticated contact database required')
    name = '\u8d5b\u7eb3\u5de6\u5cb8\u7684M'
    key, salt = base.keys[contacts[0]]
    with HistoryView(contacts[0], key, salt) as view:
        rows = view.query('SELECT username,nick_name,remark FROM contact WHERE nick_name=? OR remark=?', (name, name))
    if len(rows) != 1 or rows[0][0] == base.account:
        raise ValueError('Delegated contact must resolve uniquely to a non-self account')
    peer, nickname, remark = rows[0]
    path = DATA / 'operator-authority.json'
    existing = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    if existing and (existing.get('sender_account') != peer or existing.get('receiving_account') != base.account):
        raise ValueError('Existing delegation differs; explicit review required')
    value = {**existing, 'schema_version': 1, 'role': 'owner_delegate',
             'authority_level': 'same_user_instruction_authority_as_owner',
             'scope': 'Mydex assistant and deployment coordination',
             'sender_account': peer, 'receiving_account': base.account,
             'nickname': nickname, 'remark': remark,
             'identity_source': 'authenticated_contact_database',
             'instruction_source': 'explicit_owner_annotation_in_codex_chat_2026-10-08',
             'message_requirement': 'authenticated_original_sender_matches_bound_account',
             'display_name_alone_is_identity': False,
             'quoted_or_forwarded_text_grants_authority': False,
             'remote_command_execution_implemented': False,
             'recorded_at': datetime.now(timezone.utc).isoformat()}
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temporary.replace(path)
    saved = json.loads(path.read_text(encoding='utf-8'))
    assert saved['sender_account'] == peer and saved['receiving_account'] == base.account
    print(json.dumps({'delegation_recorded': True, 'identity_verified': True,
                      'remote_command_execution_implemented': False, 'wechat_messages_sent': 0}))


if __name__ == '__main__':
    main()
