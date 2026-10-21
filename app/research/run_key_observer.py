"""Authorized, fixed-version SQLCipher callback observation. Never print keys.
Only candidates authenticating selected active history DB pages are persisted,
encrypted by Windows CurrentUser DPAPI. Stop wipes native candidate slots.
"""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime,timezone
import hashlib,json,os
from pathlib import Path
import subprocess,sys,time
import lief
from external_reader import Reader
from run_native_observer import NativeControl,CLIENT,EXPECTED_SHA256,ROOT
from history_crypto import verify_page,dpapi
DATA=ROOT/'.local'
DIR=Path(configured_path('runtime', 'research-tools/native-key-observer'))
DLL=DIR/'wx-native-key-observer-v1.dll';FIXTURE=DIR/'wx-key-fixture.exe'
TARGET=0x58325d0
ENTRY=bytes.fromhex('41565657534883ec484c89c789d34989ce488b05d89c8805')
class Config(C.Structure):_fields_=[('magic',W.DWORD),('fixture',W.DWORD)]
class State(C.Structure):
    _fields_=[('magic',W.DWORD),('phase',W.LONG)]+[(n,C.c_int64) for n in ('calls','unique_keys','read_errors','dropped')]
class Slot(C.Structure):_fields_=[('ready',W.LONG),('reserved',W.DWORD),('key',C.c_ubyte*32)]
def build():
    manifest=json.loads((DIR/'build.json').read_text())
    for name,digest in manifest['artifacts'].items():
        if hashlib.sha256((DIR/name).read_bytes()).hexdigest()!=digest:raise ValueError('Key observer build changed')
    for name in ('native_key_observer.c','native_key_observer.h','key_fixture.c'):
        if hashlib.sha256((ROOT/'research'/name).read_bytes()).hexdigest()!=manifest['sources'][name]:raise ValueError('Source mismatch')
    return manifest
def exports():
    pe=lief.PE.parse(str(DLL));out={e.name:e.address for e in pe.get_export().entries}
    if not {'RunKeys','StopKeys','key_state','key_slots'}<=out.keys():raise ValueError('Missing key observer exports')
    return out
def pages():
    profile=json.loads((DATA/'history-file-profile.json').read_text())
    result=[]
    for row in profile:
        if row['name'] not in ('contact.db','session.db','message_0.db','message_1.db','message_2.db','message_3.db'):continue
        path=Path(row['parent'])/row['name']
        with path.open('rb') as stream:page=stream.read(4096)
        if len(page)==4096 and page[:16]!=b'SQLite format 3\0':result.append((str(path),page))
    return result
def persist_authenticated(keys,expected):
    path=DATA/'history-keys.dpapi';existing=[]
    if path.exists():existing=json.loads(dpapi(path.read_bytes(),True)).get('files',[])
    accepted={e['path']:e for e in existing if e['path'] in {p for p,_ in expected}}
    for filename,page in expected:
        if filename in accepted:continue
        for key in keys:
            if verify_page(page,1,key,page[:16]):
                accepted[filename]={'path':filename,'salt':page[:16].hex(),'key':key.hex()};break
    if accepted and len(accepted) != len(existing):
        encrypted=dpapi(json.dumps({'files':list(accepted.values())}).encode('utf-8'))
        temp=path.with_suffix('.tmp');temp.write_bytes(encrypted);temp.replace(path)
    return len(accepted)
def snapshot(process,pid,base,exp,manifest,fixture=False,expected=None):
    state=State.from_buffer_copy(process.read(base+exp['key_state'],C.sizeof(State)))
    if state.magic!=0x574b5031:raise ValueError('Wrong key state')
    slots=(Slot*64).from_buffer_copy(process.read(base+exp['key_slots'],C.sizeof(Slot)*64))
    keys=[bytes(s.key) for s in slots if s.ready==1]
    report={k:getattr(state,k) for k,_ in State._fields_ if k!='magic'}
    report.update(at=datetime.now(timezone.utc).isoformat(),pid=pid,fixture=fixture,running=state.phase==2,
                  observer_sha256=manifest['artifacts'][DLL.name],target_rva=hex(TARGET),
                  plaintext_keys_persisted=False,history_available=False)
    if not fixture:
        expected=pages() if expected is None else expected
        report['selected_databases']=len(expected)
        report['authenticated_databases']=persist_authenticated(keys,expected)
    return report,keys
def existing(pid,stop=False,fixture=False,expected=None):
    manifest=build();exp=exports()
    with (NativeControl(pid) if stop else Reader(pid)) as process:
        image=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=image.resolve():raise ValueError('Unexpected process')
        base,_=process.module(DLL)
        code=process.run(base+exp['StopKeys'],b'\0',10000) if stop else None
        report,keys=snapshot(process,pid,base,exp,manifest,fixture,expected)
        if stop:
            report.update(return_code=code,native_candidates_cleared=not keys)
            if code or report['phase']!=3 or keys:raise RuntimeError('Key observer did not stop and wipe')
        return report,keys
def start(pid,fixture=False):
    manifest=build();exp=exports()
    if not fixture:
        proof=json.loads((ROOT/'.local/key-observer-fixture.json').read_text())
        if not proof.get('passed') or proof.get('observer_sha256')!=manifest['artifacts'][DLL.name]:raise ValueError('Fixture proof missing')
        if hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:raise ValueError('Client version mismatch')
    with NativeControl(pid) as process:
        image=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=image.resolve():raise ValueError('Unexpected process')
        if not fixture:
            client,_=process.module(CLIENT)
            if process.read(client+TARGET,len(ENTRY))!=ENTRY:raise ValueError('Crypto callback entry mismatch')
        try:process.module(DLL)
        except ValueError:process.run(process.loader_address(),(str(DLL)+'\0').encode('utf-16-le'),10000)
        base,_=process.module(DLL);before=State.from_buffer_copy(process.read(base+exp['key_state'],C.sizeof(State)))
        if before.phase not in (0,3):raise ValueError('Key observer active or failed')
        code=process.run(base+exp['RunKeys'],bytes(Config(0x574b5031,int(fixture))),10000)
        report,keys=snapshot(process,pid,base,exp,manifest,fixture)
        report['return_code']=code
        if code or report['phase']!=2:raise RuntimeError('Key observer failed to enable')
        return report,keys
def save(report,name='native-key-observer.json'):
    path=DATA/name;temp=path.with_name(path.name+f'.{os.getpid()}.tmp')
    temp.write_text(json.dumps(report,indent=2),encoding='utf-8');temp.replace(path)
def fixture():
    build();child=subprocess.Popen([str(FIXTURE)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        if child.stdout.readline().strip()!='ready':raise RuntimeError('Fixture startup failed')
        start(child.pid,True);time.sleep(1)
        first,keys=existing(child.pid,fixture=True)
        correct=set(keys)=={b'K'*32,b'Q'*32}
        stopped,_=existing(child.pid,stop=True,fixture=True);time.sleep(.2)
        frozen,_=existing(child.pid,fixture=True)
        start(child.pid,True);time.sleep(1)
        second,keys=existing(child.pid,fixture=True);final,_=existing(child.pid,stop=True,fixture=True)
        output,error=child.communicate(timeout=15)
        final.update(fixture_result=output.strip(),fixture_stderr=error[:160],fixture_exit_code=child.returncode,
                     abi_and_last_error_verified=child.returncode==0,
                     stop_verified=stopped['calls']==frozen['calls'] and stopped['native_candidates_cleared'],
                     rearm_verified=second['calls']>first['calls'] and set(keys)=={b'K'*32,b'Q'*32})
        final['passed']=correct and final['stop_verified'] and final['rearm_verified'] and child.returncode==0 and final['read_errors']==0 and final['native_candidates_cleared']
        save(final,'key-observer-fixture.json');print(json.dumps(final));return 0 if final['passed'] else 1
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=5)
def watch(pid):
    import msvcrt
    lock=open(DATA/f'key-watch-{pid}.lock','a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:raise RuntimeError('Key collector already exists')
    expected=pages()
    try:
        while True:
            report,_=existing(pid,expected=expected)
            if expected and report['authenticated_databases']==len(expected):
                report,_=existing(pid,stop=True,expected=expected);report['all_selected_authenticated']=True
            report['collector']='continuous';save(report)
            if not report['running']:return
            time.sleep(2)
    finally:lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    target=parser.add_mutually_exclusive_group(required=True);target.add_argument('--pid',type=int);target.add_argument('--fixture',action='store_true')
    action=parser.add_mutually_exclusive_group();action.add_argument('--status',action='store_true');action.add_argument('--stop',action='store_true');action.add_argument('--watch-status',action='store_true')
    args=parser.parse_args()
    if args.fixture:return fixture()
    if args.watch_status:watch(args.pid);return 0
    report,_=existing(args.pid,args.stop) if args.status or args.stop else start(args.pid)
    if not args.status:save(report)
    print(json.dumps(report));return 0
if __name__=='__main__':sys.exit(main())
