"""Read-only checks. Never installs hooks or starts/sends to WeChat."""
import hashlib
import importlib
import json
import platform
from pathlib import Path
import sys

APP = Path(__file__).resolve().parents[1] / 'app'
EXPECTED = '10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5'

def main():
    checks = {'windows_x64_python312': sys.platform == 'win32' and platform.machine().lower() in ('amd64','x86_64') and sys.version_info[:2] == (3,12)}
    for name in ('psutil','apsw','Crypto','cryptography','zstandard','lief'):
        try:
            importlib.import_module(name)
            checks[name] = True
        except (ImportError,OSError):
            checks[name] = False
    sys.path.insert(0, str(APP))
    try:
        from probe_native import CLIENT
        checks['client_exact_hash'] = CLIENT.is_file() and hashlib.sha256(CLIENT.read_bytes()).hexdigest() == EXPECTED
    except ImportError:
        checks['client_exact_hash'] = False
    data = APP / '.local/quote-m-session'
    required = ['session.json','history-file-profile.json','history-keys.dpapi',
                'quote-sample-evidence.json','group-binding.json','monitored-groups.json',
                'reply-scope.json','native-sender-settings.json','native-delivery-proof.json']
    checks['account_files_present'] = all((data/name).is_file() for name in required)
    checks['model_credential_present'] = (APP/'.local/paratera-api-key.dpapi').is_file()
    checks['native_fixture_proof_present'] = (APP/'.local/account-sender-fixture.json').is_file()
    checks['live_binding_valid'] = False
    if all(checks.values()) or (all(v for k,v in checks.items() if k!='live_binding_valid')):
        try:
            from m_session_assistant import check_session
            from session_history import SessionHistory
            from account_scope import load_scope
            check_session(json.loads((data/'session.json').read_text(encoding='utf-8')))
            SessionHistory(data)
            scope = load_scope(data)
            if not scope.get('all_groups_mentions'):
                raise ValueError('Requested reply policy missing')
            from research.worker_sender_v6.run import verified,action
            manifest = verified(False)
            session = json.loads((data/'session.json').read_text(encoding='utf-8'))
            config = json.loads((data/'native-sender-settings.json').read_text(encoding='utf-8'))
            proof = json.loads((data/'native-delivery-proof.json').read_text(encoding='utf-8'))
            if (config.get('sender_version') != 6 or config.get('enabled') is not True
                    or config.get('account_verified') is not True
                    or config.get('pid') != session['pid'] or config.get('process_created') != session['created']
                    or config.get('sender_sha256') != manifest['artifacts']['wx-worker-sender-v6.dll']
                    or proof.get('pid') != session['pid'] or proof.get('process_created') != session['created']
                    or not proof.get('server_record_verified') or not proof.get('native_delivery_verified')
                    or not any(m.get('room_id') == session['allowed_room'] for m in proof.get('matches', []))):
                raise ValueError('Native proof belongs to another session or is incomplete')
            from lab import Settings
            from api_credentials import load_key
            settings = Settings().get()
            if (settings['provider'] != 'api' or settings['model'] != 'Qwen3.8-Flash'
                    or settings['api_base'] != 'https://llmapi.paratera.com/v1'
                    or settings['api_credential'] != 'paratera' or settings['api_enable_thinking'] is not False
                    or settings['conversation_enabled'] is not False or not settings['group_model_authorized']):
                raise ValueError('Model or reply policy differs from deployment configuration')
            load_key(APP/'.local/paratera-api-key.dpapi', settings['api_base'])
            status = action(session['pid'],'status',data=data)
            checks['live_binding_valid'] = status['phase']==2 and bool(status['worker_thread'])
        except Exception:
            pass
    print(json.dumps({'checks':checks,'ready':all(checks.values()),'sends_performed':0},indent=2))
    return 0 if all(checks.values()) else 2

if __name__ == '__main__':
    raise SystemExit(main())
