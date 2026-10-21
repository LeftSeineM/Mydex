"""Bind the already-authorized contact to a current-thread heartbeat."""
import argparse
import json
from pathlib import Path
import sys
import time

APP = Path(__file__).resolve().parents[1]/'app'
sys.path.insert(0,str(APP))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--thread-id',required=True)
    parser.add_argument('--automation-id',required=True)
    args=parser.parse_args()
    from m_session_assistant import DATA,check_session
    from session_history import SessionHistory
    from account_scope import stable_read,validate_recipient
    session=json.loads((DATA/'session.json').read_text(encoding='utf-8'))
    check_session(session)
    base=stable_read(lambda:SessionHistory(DATA))
    authority=json.loads((DATA/'operator-authority.json').read_text(encoding='utf-8'))
    if authority['receiving_account']!=base.account or authority.get('authority_level')!='same_user_instruction_authority_as_owner':
        raise ValueError('Owner delegation not bound to current account')
    entry=validate_recipient(DATA,authority['sender_account'])
    if entry['kind']!='direct':raise ValueError('Direct operator contact required')
    path=DATA/'desktop-operator.json'
    if path.exists():raise ValueError('Existing bridge requires explicit review; do not reset activation cursor')
    config={'enabled':True,'sender_account':authority['sender_account'],'receiving_account':base.account,
            'pid':session['pid'],'process_created':session['created'],'activated_at':time.time(),
            'thread_id':args.thread_id,'automation_id':args.automation_id,'backend':'current_codex_thread'}
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(config,ensure_ascii=False,indent=2),encoding='utf-8')
    temporary.replace(path)
    print(json.dumps({'bridge_configured':True,'new_messages_only':True,'independent_gpt_credentials_needed':False}))


if __name__=='__main__':main()
