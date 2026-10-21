"""Explicit local enrollment; no automatic sending or guessed process identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import sys
import time

APP = Path(__file__).resolve().parents[1] / 'app'
sys.path[:0] = [str(APP), str(APP / 'research')]
DATA = APP / '.local/quote-m-session'


def save(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(path)


def prepare():
    import psutil
    from inspect_open_databases import inventory
    from find_history_keys import scan
    from run_native_observer import CLIENT, EXPECTED_SHA256
    if hashlib.sha256(CLIENT.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise ValueError('Unsupported client hash')
    candidates = []
    for proc in psutil.process_iter(['name', 'exe']):
        if (proc.info['name'] or '').lower() != 'weixin.exe':
            continue
        if Path(proc.info['exe']).resolve() != (CLIENT.parent.parent / 'Weixin.exe').resolve():
            continue
        paths = inventory(proc.pid)['database_paths']
        roots = {str(Path(p).parents[2]) for p in paths
                 if 'db_storage' in Path(p).parts and Path(p).suffix == '.db'}
        if roots:
            candidates.append((proc, paths, roots))
    if len(candidates) != 1 or len(candidates[0][2]) != 1:
        raise ValueError('Exactly one logged-in account is required')
    proc, paths, roots = candidates[0]
    root = Path(next(iter(roots)))
    if not re.fullmatch(r'wxid_[A-Za-z0-9]+_[0-9a-fA-F]{4}', root.name):
        raise ValueError('Unsupported account directory format')
    DATA.mkdir(parents=True, exist_ok=True)
    pending = DATA / 'enrollment-pending'
    pending.mkdir(exist_ok=True)
    if (pending / 'session.json').exists():
        from m_session_assistant import check_session
        session = json.loads((pending / 'session.json').read_text(encoding='utf-8'))
        check_session(session)
    else:
        session = {'pid': proc.pid, 'created': proc.create_time(), 'account_roots': [str(root)],
                   'group': '\u5c0f\u72d7\u548c\u5c0f\u732b\u7684\u5de5\u4f5c\u57fa\u5730',
                   'enrollment_started': time.time(), 'verification_marker': 'Mydex-bind-' + secrets.token_hex(4)}
        save(pending / 'session.json', session)
    profile = [{'name': Path(p).name, 'parent': str(Path(p).parent)} for p in paths
               if root in Path(p).parents and
               (Path(p).name == 'contact.db' or re.fullmatch(r'message_[0-3]\.db', Path(p).name))]
    if not any(p['name'] == 'contact.db' for p in profile):
        raise ValueError('Active contact database missing')
    save(pending / 'history-file-profile.json', profile)
    result = scan(proc.pid, pending)
    print(json.dumps({k: result[k] for k in ('authenticated_databases', 'active_databases', 'elapsed_seconds')}))
    if result['authenticated_databases'] != result['active_databases']:
        print(json.dumps({'phase': 'needs_callback_authentication', 'marker': session['verification_marker']}))
        return
    from history_crypto import dpapi
    from history_vfs import HistoryView
    private = json.loads(dpapi((pending / 'history-keys.dpapi').read_bytes(), True))
    contacts = [p for p in private['files'] if Path(p['path']).name == 'contact.db']
    if len(contacts) != 1:
        raise ValueError('Contact database not authenticated')
    item = contacts[0]
    with HistoryView(item['path'], bytes.fromhex(item['key']), bytes.fromhex(item['salt'])) as view:
        rows = view.query('SELECT username,nick_name,is_in_chat_room FROM contact WHERE nick_name=?', (session['group'],))
    rows = [r for r in rows if r[2] and re.fullmatch(r'\d+@chatroom', r[0])]
    if len(rows) != 1:
        raise ValueError('Target group name must match one joined contact record')
    session['allowed_room'] = rows[0][0]
    save(pending / 'session.json', session)
    print(json.dumps({'phase': 'waiting_for_self_marker', 'group_contact_verified': True,
                      'current_pinned_group_matches': session['allowed_room'] == '90000000003@chatroom',
                      'marker': session['verification_marker'], 'sends_performed': 0}))


def observe():
    from m_session_assistant import check_session
    import run_key_observer as observer
    pending = DATA / 'enrollment-pending'
    session = json.loads((pending / 'session.json').read_text(encoding='utf-8'))
    check_session(session)
    observer.DATA = pending
    report, _ = observer.start(session['pid'])
    observer.save(report)
    print(json.dumps({'phase': 'waiting_for_database_activity', 'marker': session['verification_marker']}), flush=True)
    expected = observer.pages()
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            check_session(session)
            report, _ = observer.existing(session['pid'], expected=expected)
            observer.save(report)
            if report['authenticated_databases'] == len(expected):
                break
            time.sleep(2)
    finally:
        report, _ = observer.existing(session['pid'], stop=True, expected=expected)
        observer.save(report)
        print(json.dumps({'authenticated_databases': report['authenticated_databases'],
                          'selected_databases': len(expected),
                          'native_candidates_cleared': report['native_candidates_cleared']}), flush=True)


def finalize():
    from m_session_assistant import check_session
    from history_crypto import dpapi
    from history_vfs import HistoryView
    from history_reader import text_value
    from session_history import SessionHistory
    from account_scope import discover
    from lab import Settings
    import shutil
    pending = DATA / 'enrollment-pending'
    session = json.loads((pending / 'session.json').read_text(encoding='utf-8'))
    check_session(session)
    account = re.fullmatch(r'(wxid_[A-Za-z0-9]+)_[0-9a-fA-F]{4}', Path(session['account_roots'][0]).name).group(1)
    table = 'Msg_' + hashlib.md5(session['allowed_room'].encode()).hexdigest()
    private = json.loads(dpapi((pending / 'history-keys.dpapi').read_bytes(), True))
    samples = []
    for item in private['files']:
        if not re.fullmatch(r'message_\d+\.db', Path(item['path']).name):
            continue
        with HistoryView(item['path'], bytes.fromhex(item['key']), bytes.fromhex(item['salt'])) as view:
            if not view.query('SELECT name FROM sqlite_master WHERE name=?', (table,)):
                continue
            rows = view.query('SELECT m.server_id,m.create_time,n.user_name,m.message_content,m.compress_content '
                              'FROM "' + table + '" m LEFT JOIN Name2Id n ON n.rowid=m.real_sender_id '
                              'WHERE m.local_type=1 AND m.create_time>=? ORDER BY m.local_id DESC LIMIT 200',
                              (session['enrollment_started'],))
            for server, created, sender, body, compressed in rows:
                content = text_value(body) or text_value(compressed)
                if content.startswith(account + ':\n'):
                    content = content[len(account) + 2:]
                if sender == account and server and int(server) > 0 and content == session['verification_marker']:
                    samples.append({'type': 1, 'server_id': str(server), 'text': content, 'created': created})
    if not samples:
        print(json.dumps({'phase': 'waiting_for_self_marker', 'marker': session['verification_marker']}))
        return
    save(pending / 'quote-sample-evidence.json', {'account': account, 'room': session['allowed_room'], 'samples': samples})
    base = SessionHistory(pending)
    save(pending / 'group-binding.json', base.binding())
    save(pending / 'monitored-groups.json', [{'room_id': base.room, 'name': base.name,
         'configured_name': base.name, 'group_model_authorized': True}])
    save(pending / 'reply-scope.json', {'pid': session['pid'], 'process_created': session['created'],
         'account_root': session['account_roots'][0], 'activated_at': time.time(),
         'all_groups_mentions': True, 'all_direct_messages': True, 'source': 'explicit_user_request'})
    files = ['session.json', 'history-file-profile.json', 'history-keys.dpapi', 'quote-sample-evidence.json',
             'group-binding.json', 'monitored-groups.json', 'reply-scope.json']
    if any((DATA / name).exists() for name in files):
        raise ValueError('Existing enrollment retained; archive explicitly before rebinding')
    for name in files:
        shutil.copy2(pending / name, DATA / name)
    registry = discover(SessionHistory(DATA), DATA)
    Settings().update({'group': base.name, 'group_model_authorized': True, 'conversation_enabled': False})
    save(DATA / 'cutover-confirmed.json', {'old_assistant_stopped': True,
         'source': 'user_confirmed_in_chat_2026-10-08', 'at': time.time()})
    print(json.dumps({'phase': 'account_authenticated', 'self_server_record_verified': True,
                      'discovered_conversations': len(registry), 'sends_performed': 0}))


def install_sender():
    from m_session_assistant import check_session
    from session_history import SessionHistory
    from research.worker_sender_v6.run import action
    session = json.loads((DATA / 'session.json').read_text(encoding='utf-8'))
    check_session(session)
    SessionHistory(DATA)
    intent = DATA / 'native-install-intent.json'
    if intent.exists():
        state = action(session['pid'], 'status', data=DATA)
    else:
        save(intent, {'pid': session['pid'], 'created': session['created'], 'at': time.time()})
        state = action(session['pid'], 'install', data=DATA)
        if state.get('return_code') != 0:
            raise ValueError('Native install failed; inspect intent, never automatically retry')
    if state.get('phase') != 2:
        raise ValueError('Sender not ready')
    save(DATA / 'native-sender-settings.json', {'enabled': False, 'pid': session['pid'],
         'process_created': session['created'], 'sender_version': 6,
         'sender_sha256': state['sender_sha256'], 'account_verified': True, 'group_id': session['allowed_room']})
    print(json.dumps({'phase': 'worker_bound' if state.get('worker_thread') else 'waiting_for_desktop_send',
                      'sends_performed': 0}))


def prove_sender():
    from m_session_assistant import check_session, matches
    from session_history import SessionHistory
    from research.worker_sender_v6.run import action
    session = json.loads((DATA / 'session.json').read_text(encoding='utf-8'))
    check_session(session)
    base = SessionHistory(DATA)
    state = action(session['pid'], 'status', data=DATA)
    if state.get('phase') != 2 or not state.get('worker_thread'):
        raise ValueError('A fresh desktop send must bind the worker first')
    path = DATA / 'connectivity-send-intent.json'
    if path.exists():
        intent = json.loads(path.read_text(encoding='utf-8'))
        if intent['pid'] != session['pid'] or intent['process_created'] != session['created']:
            raise ValueError('Stale send intent; manual review required')
    else:
        intent = {'pid': session['pid'], 'process_created': session['created'], 'at': time.time(),
                  'body': 'Mydex: \u672c\u673a\u53d1\u9001\u8fde\u901a\u9a8c\u8bc1 ' + secrets.token_hex(3),
                  'cursors': {p: base.latest_cursor(p, base.name) for p in base.message_paths()}}
        save(path, intent)
        queued = action(session['pid'], 'send', intent['body'], room=base.room, data=DATA)
        if queued.get('return_code') != 0:
            raise ValueError('Send outcome uncertain; preserved intent will not be sent again')
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        check_session(session)
        event = matches(base, intent['body'], intent['at'], intent['cursors'])
        if event:
            save(DATA / 'native-delivery-proof.json', {'pid': session['pid'], 'process_created': session['created'],
                 'server_record_verified': True, 'native_delivery_verified': True, 'account_id': base.account,
                 'matches': [{'room_id': base.room, 'server_id': event['id']}], 'at': time.time()})
            cfg = json.loads((DATA / 'native-sender-settings.json').read_text(encoding='utf-8'))
            save(DATA / 'native-sender-settings.json', {**cfg, 'enabled': True})
            print(json.dumps({'phase': 'native_send_verified', 'server_record_verified': True}))
            return
        time.sleep(.5)
    raise ValueError('Send outcome unconfirmed; no automatic retry')


if __name__ == '__main__':
    try:
        if '--new-session' in sys.argv:
            pending = DATA / 'enrollment-pending'
            if pending.exists():
                state = pending / 'native-key-observer.json'
                if state.exists() and json.loads(state.read_text(encoding='utf-8')).get('running'):
                    raise ValueError('Stop the current observer before changing enrollment')
                pending.rename(DATA / ('enrollment-previous-' + str(time.time_ns())))
        if '--observe' in sys.argv:
            observe()
        elif '--finalize' in sys.argv:
            finalize()
        elif '--install-sender' in sys.argv:
            install_sender()
        elif '--prove-sender' in sys.argv:
            prove_sender()
        else:
            prepare()
    except Exception as exc:
        print(json.dumps({'phase': 'needs_attention', 'error_type': type(exc).__name__}))
        raise SystemExit(2)
