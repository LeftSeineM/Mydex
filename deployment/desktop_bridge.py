"""Current-thread bridge CLI. Never executes messages as shell commands."""
import argparse
import json
from pathlib import Path
import sys
import time

APP = Path(__file__).resolve().parents[1] / 'app'
sys.path.insert(0, str(APP))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['pending', 'claim', 'complete', 'status'])
    parser.add_argument('--id')
    parser.add_argument('--response-file', type=Path)
    args = parser.parse_args()
    from desktop_operator import DesktopBridge
    from m_session_assistant import DATA, check_session
    from account_scope import validate_recipient
    from lab import Settings, Store
    bridge = DesktopBridge(DATA)
    cfg = bridge.config()
    if not cfg or cfg.get('enabled') is not True:
        raise ValueError('Desktop bridge not enabled')
    runtime = json.loads((DATA/'assistant-status.json').read_text(encoding='utf-8'))
    if (DATA/'stop.request').exists() or runtime.get('phase') != 'running' or time.time()-runtime.get('at',0)>30:
        raise ValueError('Assistant must be running with fresh health before handling tasks')
    session = json.loads((DATA / 'session.json').read_text(encoding='utf-8'))
    if session['pid'] != cfg['pid'] or session['created'] != cfg['process_created']:
        raise ValueError('Desktop bridge requires session revalidation')
    check_session(session)
    entry = validate_recipient(DATA, cfg['sender_account'])
    if not bridge.selected(entry, cfg['receiving_account']):
        raise ValueError('Operator identity no longer matches')
    if args.action == 'pending':
        result = {'tasks': bridge.pending()}
    elif args.action == 'claim':
        result = bridge.claim(args.id)
    elif args.action == 'complete':
        if not args.response_file:
            raise ValueError('Response file required')
        store = Store(DATA / 'history.sqlite3')
        try:
            result = bridge.complete(args.id, args.response_file.read_text(encoding='utf-8-sig'), store, Settings().get()['bot_name'])
        finally:
            store.db.close()
    else:
        result = bridge.status(args.id)
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'error_type': type(exc).__name__}))
        raise SystemExit(1)
