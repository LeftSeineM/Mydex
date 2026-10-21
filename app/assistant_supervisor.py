"""Keep this authorized local assistant running after Windows sign-in.

No UI automation, web login, account switching, or automatic message replay.
The native sender is tied to the exact client version and the proven group.
After a new client session, an authenticated self-sent group record and a
native worker-thread match are required before enabling replies.
"""
from datetime import datetime,timezone
import json
import msvcrt
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import psutil

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'research'))
from run_native_observer import CLIENT
from external_reader import Reader
from research.worker_sender_v4.run import action
from group_scopes import ALLOWED_ROOMS,scopes
from lab import Settings
from history_reader import TargetHistory
DATA=ROOT/'.local'
BASE='http://127.0.0.1:8769'
EXPECTED_EXE=(CLIENT.parent.parent/'Weixin.exe').resolve()

def report(**values):
    values['at']=datetime.now(timezone.utc).isoformat()
    path=DATA/'assistant-supervisor.json'
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(values,ensure_ascii=False,indent=2),encoding='utf-8')
    temporary.replace(path)

def main_process():
    candidates=[]
    for proc in psutil.process_iter(['pid','name','exe','cmdline','create_time']):
        try:
            if (proc.info['name'] or '').lower()!='weixin.exe':continue
            args=' '.join(proc.info['cmdline'] or [])
            if re.search(r'--type=|crash',args,re.I):continue
            if Path(proc.info['exe']).resolve()==EXPECTED_EXE:candidates.append(proc)
        except (psutil.AccessDenied,psutil.NoSuchProcess,TypeError):continue
    if len(candidates)>1:raise ValueError('Multiple main clients; select one manually')
    return candidates[0] if candidates else None

def api(path,data=None):
    if data is None:
        with urllib.request.urlopen(BASE+path,timeout=6) as response:return json.load(response)
    with urllib.request.urlopen(BASE,timeout=5) as response:html=response.read(300000).decode('utf-8')
    token=re.search(r'<meta name="lab-token" content="([^"]+)"',html).group(1)
    request=urllib.request.Request(BASE+path,json.dumps(data).encode(),
            {'Content-Type':'application/json','X-Lab-Token':token},method='POST')
    with urllib.request.urlopen(request,timeout=6) as response:return json.load(response)

def panel_state():
    try:
        state=api('/api/state')
        if not all(k in state for k in ('native_sender','database_inbox','settings')):
            raise ValueError('Unexpected local service')
        return state
    except (OSError,ValueError):return None

def panel_alive():
    try:
        state=api('/api/health')
        return state.get('service')=='wechat-group-lab' and state.get('status')=='ok'
    except (OSError,ValueError):return False

def start_panel():
    # Check the port before spawning. Never stop an unrelated port owner.
    for item in psutil.net_connections(kind='tcp'):
        if item.laddr and item.laddr.port==8769 and item.status==psutil.CONN_LISTEN:
            if not panel_alive():raise ValueError('Port 8769 belongs to another service')
            return
    flags=subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.CREATE_BREAKAWAY_FROM_JOB
    with (DATA/'panel-background.stdout.log').open('ab') as out,(DATA/'panel-background.stderr.log').open('ab') as err:
        subprocess.Popen([sys.executable,'-u',str(ROOT/'server.py')],cwd=ROOT,stdin=subprocess.DEVNULL,
                         stdout=out,stderr=err,creationflags=flags,close_fds=True)

def write_binding(pid,created,status):
    path=DATA/'native-sender-settings.json'
    previous=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    config={'enabled':previous.get('enabled',True),'pid':pid,'process_created':created,
            'group_id':'90000000003@chatroom','account_verified':True,
            'sender_sha256':status['sender_sha256'],'source':'user_authorized_local_autostart'}
    path=DATA/'native-sender-settings.json';temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(config,indent=2),encoding='utf-8');temporary.replace(path)

def activate_panel_binding(pid,created,status):
    state=panel_state()
    if state and not state['native_sender'].get('requested_enabled',state['native_sender'].get('enabled')):
        return
    write_binding(pid,created,status)
    if state:
        if state['native_sender'].get('pid')!=pid or state.get('monitoring_waiting_for_binding'):
            # The new session was verified before modifying the live service.
            api('/api/native/bind',{'pid':pid,'process_created':created})
        elif not state['native_sender'].get('enabled'):
            # A user pause persists; the supervisor never overrides it.
            return
        if not state['database_inbox']['running']:
            return  # Explicit pause is not a request to restart monitoring.
    else:start_panel()

def authenticated_new_self(reader,after):
    group=reader.name
    if reader.room not in ALLOWED_ROOMS:raise ValueError('Configured group differs')
    for path in reader.message_paths():
        for event in reader.fetch(path,group)['events']:
            if (event.get('is_self') is True and event.get('type')=='text' and event['created']>=after
                    and event['id'].isdigit() and int(event['id'])):
                return True
    return False

def claim_install_attempt(pid, created):
    """One automatic install attempt per OS client session, including restarts."""
    path=DATA/'native-install-attempt.json'
    previous=json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    if previous.get('pid')==pid and previous.get('process_created')==created:
        raise ValueError('Native install already attempted; inspect locally before retry')
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'pid':pid,'process_created':created,'at':time.time()}),encoding='utf-8')
    temporary.replace(path)

def main():
    DATA.mkdir(exist_ok=True)
    lock=open(DATA/'assistant-supervisor.lock','a+b')
    lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:
        print('The local supervisor is already running.');return 0
    session=None;installed_at=0;ready=False;reader=None;last_check=0;failures=0
    try:
        while True:
            try:
                proc=main_process()
                if not proc:
                    report(phase='waiting_for_wechat',message='请打开电脑微信并登录；本机启动器正在等待')
                    session=None;ready=False;reader=None
                    time.sleep(5);continue
                current=(proc.pid,proc.create_time())
                if session!=current:
                    # A just-starting client may not have loaded its native
                    # module yet. Check before pinning any shim into it.
                    with Reader(proc.pid) as native_process:native_process.module(CLIENT)
                    session=current;ready=False;reader=None;installed_at=time.time()
                    try:native=action(proc.pid,'status')
                    except ValueError:
                        claim_install_attempt(*current)
                        native=action(proc.pid,'install')
                        if native.get('return_code')!=0:raise ValueError('Native install not ready')
                    # A proven sender still running in its original process may
                    # resume without another manual message.
                    config=json.loads((DATA/'native-sender-settings.json').read_text(encoding='utf-8'))
                    creation_matches=config.get('process_created')==current[1]
                    ready=(config.get('account_verified') is True and config.get('pid')==proc.pid and creation_matches and native.get('worker_thread')
                           and native.get('phase')==2)
                    if ready:activate_panel_binding(*current,native)
                native=action(proc.pid,'status')
                if not ready and native.get('worker_thread') and native.get('phase')==2:
                    if reader is None:
                        reader=[TargetHistory(group=entry['configured_name']) for entry in scopes(Settings())]
                    if any(authenticated_new_self(r,installed_at-1) for r in reader):
                        ready=True;activate_panel_binding(*current,native)
                if ready:
                    if time.monotonic()-last_check>=15:
                        last_check=time.monotonic()
                        if not panel_alive():start_panel()
                    report(phase='running',pid=proc.pid,groups=[g['name'] for g in scopes(Settings())],
                           message='指定群正在监听，真正 @ 当前微信账号会触发 Mydex：回复')
                else:
                    report(phase='waiting_for_group_binding',pid=proc.pid,
                           message='请用这台电脑微信在任一监听群发一句话，验证本机账号并绑定新会话发送线程')
                failures=0
            except Exception as exc:
                if not ready:session=None
                failures=min(failures+1,5)
                report(phase='waiting_or_error',error=type(exc).__name__,
                       retry_in_seconds=min(60,5*2**failures),
                       message='检查未通过，已降低重试频率；同一会话不会反复尝试注入，请查看本机状态面板')
            time.sleep(min(60,5*2**failures))
    finally:
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()

if __name__=='__main__':raise SystemExit(main())
