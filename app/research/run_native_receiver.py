"""Version-pinned continuous exact-sample receive research, no sends.

Separate build, proof, state and watcher from the working outbound observer.
"""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import lief
from external_reader import Reader
from run_native_observer import NativeControl,CLIENT,EXPECTED_SHA256,ROOT
from decode_receive import decode_add_message,DecodeError
DIRECTORY=Path(configured_path('runtime', 'research-tools/native-receiver'))
DLL=DIRECTORY/'wx-native-receiver-v2.dll'
FIXTURE=DIRECTORY/'wx-receive-fixture.exe'
TARGET=0x2e7caf0
ENTRY=bytes.fromhex('5541574156415541545657534883ec38488d6c243048c745')
MARKER='WXRECV1006'
class Config(C.Structure):
    _fields_=[('magic',W.DWORD),('fixture',W.DWORD),('room',C.c_char*128),('marker',C.c_char*64)]
class State(C.Structure):
    _fields_=[('magic',W.DWORD),('phase',W.LONG)]+[(n,C.c_int64) for n in
                 ('calls','succeeded','read_errors','room_matches','marker_matches','captured','dropped','oversize')]
class Slot(C.Structure):
    _fields_=[('sequence',C.c_int64),('command_id',W.DWORD),('length',W.DWORD),
              ('thread_id',W.DWORD),('reserved',W.DWORD),('captured_ms',C.c_uint64),('payload',C.c_ubyte*16384)]
class Command(C.Structure):
    _fields_=[('ready',W.LONG),('command_id',W.DWORD),('hits',C.c_int64)]

def build():
    manifest=json.loads((DIRECTORY/'build.json').read_text())
    for name,digest in manifest['artifacts'].items():
        if hashlib.sha256((DIRECTORY/name).read_bytes()).hexdigest()!=digest:raise ValueError('Receiver build changed')
    for name in ('native_receiver.c','native_receiver.h','receive_fixture.c'):
        if hashlib.sha256((ROOT/'research'/name).read_bytes()).hexdigest()!=manifest['sources'][name]:
            raise ValueError('Receiver source differs; rebuild required')
    return manifest
def export_map():
    pe=lief.PE.parse(str(DLL))
    exports={entry.name:entry.address for entry in pe.get_export().entries}
    if not {'RunReceive','StopReceive','receive_state','receive_slots','receive_commands'}<=exports.keys():
        raise ValueError('Receiver exports missing')
    return exports
def room_from_evidence():
    evidence=json.loads((ROOT/'.local/outbound-sample-evidence.json').read_text(encoding='utf-8-sig'))
    if evidence['snapshot']['matches']<1 or evidence['marker']!='WXPAIR1006':raise ValueError('Group evidence missing')
    room=evidence['room_id_candidate']
    if not room.endswith('@chatroom') or not room[:-9].isdigit():raise ValueError('Invalid group evidence')
    return room
def save(report,name='native-receiver.json'):
    path=ROOT/'.local'/name;temporary=path.with_name(path.name+f'.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');temporary.replace(path)
def snapshot(process,pid,base,exports,manifest,room,fixture=False):
    state=State.from_buffer_copy(process.read(base+exports['receive_state'],C.sizeof(State)))
    if state.magic!=0x57524331:raise ValueError('Invalid receiver state')
    report={name:getattr(state,name) for name,_ in State._fields_ if name!='magic'}
    report.update(at=datetime.now(timezone.utc).isoformat(),pid=pid,fixture=fixture,running=state.phase==2,
                  target_rva=hex(TARGET),receiver_sha256=manifest['artifacts'][DLL.name],
                  sending_enabled=False,receive_verified=False,history_available=False,expires_at=None)
    commands=(Command*32).from_buffer_copy(process.read(base+exports['receive_commands'],C.sizeof(Command)*32))
    report['commands']=[{'command_id':x.command_id,'hits':x.hits} for x in commands if x.ready==1]
    report['samples']=[];report['decode_rejections']=0;report['unstable_slots']=0
    # Read each bounded slot and recheck its publication sequence. Never write
    # back an acknowledgement into the client; overwrites are visible by gaps.
    for index in range(16):
        address=base+exports['receive_slots']+index*C.sizeof(Slot)
        first=int.from_bytes(process.read(address,8),'little')
        if not first or first%2:continue
        slot=Slot.from_buffer_copy(process.read(address,C.sizeof(Slot)))
        last=int.from_bytes(process.read(address,8),'little')
        if slot.sequence!=first or last!=first or not 0<slot.length<=16384:
            report['unstable_slots']+=1;continue
        try:
            event=decode_add_message(bytes(slot.payload[:slot.length]),room)
            event.update(sequence=first//2,command_id=slot.command_id,thread_id=slot.thread_id,
                         captured_ms=slot.captured_ms,payload_sha256=hashlib.sha256(bytes(slot.payload[:slot.length])).hexdigest())
            report['samples'].append(event)
        except (DecodeError,UnicodeDecodeError):report['decode_rejections']+=1
    report['samples'].sort(key=lambda x:x['sequence'])
    report['sample_marker_matches']=sum(s['content']==MARKER for s in report['samples'])
    report['capture_scope']='target_group'
    report['receive_verified']=bool(report['samples']) and not fixture
    return report
def existing(pid,stop=False,fixture=False):
    manifest=build();exports=export_map();room='123456@chatroom' if fixture else room_from_evidence()
    with (NativeControl(pid) if stop else Reader(pid)) as process:
        expected=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=expected.resolve():raise ValueError('Unexpected process')
        base,_=process.module(DLL)
        code=process.run(base+exports['StopReceive'],b'\0',10000) if stop else None
        report=snapshot(process,pid,base,exports,manifest,room,fixture)
        if stop:
            report['return_code']=code
            if code or report['phase']!=3:raise RuntimeError('Receive observer did not stop')
        return report
def start(pid,fixture=False):
    manifest=build();exports=export_map();room='123456@chatroom' if fixture else room_from_evidence()
    if not fixture:
        proof=json.loads((ROOT/'.local/native-receiver-fixture.json').read_text())
        if not proof.get('passed') or proof.get('receiver_sha256')!=manifest['artifacts'][DLL.name]:
            raise ValueError('This build has not passed its own-process fixture')
        if hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:raise ValueError('Unsupported client build')
    with NativeControl(pid) as process:
        expected=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=expected.resolve():raise ValueError('Unexpected process')
        if not fixture:
            client_base,_=process.module(CLIENT)
            if process.read(client_base+TARGET,len(ENTRY))!=ENTRY:raise ValueError('Parser entry mismatch')
        try:process.module(DLL)
        except ValueError:process.run(process.loader_address(),(str(DLL)+'\0').encode('utf-16-le'),10000)
        base,_=process.module(DLL)
        before=State.from_buffer_copy(process.read(base+exports['receive_state'],C.sizeof(State)))
        if before.phase not in (0,3):raise ValueError('Receiver is already running or has failed')
        config=Config(0x57524331,int(fixture),room.encode('ascii'),b'')
        code=process.run(base+exports['RunReceive'],bytes(config),10000)
        report=snapshot(process,pid,base,exports,manifest,room,fixture)
        report['return_code']=code
        if code or report['phase']!=2:raise RuntimeError('Receiver did not enable: '+str(code))
        return report
def public(report):
    return {k:v for k,v in report.items() if k!='samples'}
def watch(pid):
    import msvcrt
    lock=open(ROOT/'.local'/f'receive-watch-{pid}.lock','a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:raise RuntimeError('Receiver collector already exists')
    last_sequence=0;previous=None
    try:
        while True:
            try:report=existing(pid)
            except (OSError,ValueError) as exc:
                report={'at':datetime.now(timezone.utc).isoformat(),'pid':pid,'running':False,'phase':'unavailable',
                        'error':type(exc).__name__,'sending_enabled':False,'receive_verified':False,'samples':[]}
            report['collector']='continuous';save(report)
            new=[s for s in report['samples'] if s['sequence']>last_sequence]
            if new:
                with (ROOT/'.local/receive-sample-events.jsonl').open('a',encoding='utf-8') as log:
                    for event in new:
                        log.write(json.dumps({'pid':pid,'at':report['at'],**event},ensure_ascii=False)+'\n')
                last_sequence=new[-1]['sequence']
            key=(report['phase'],report.get('calls'),report.get('captured'),report.get('read_errors'))
            if key!=previous:
                with (ROOT/'.local/native-receiver-events.jsonl').open('a',encoding='utf-8') as log:
                    log.write(json.dumps(public(report))+'\n')
                previous=key
            if not report['running']:return
            time.sleep(2)
    finally:
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()
def fixture():
    build()
    child=subprocess.Popen([str(FIXTURE)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        if child.stdout.readline().strip()!='ready':raise RuntimeError('Fixture did not start')
        start(child.pid,True);time.sleep(1.5)
        first=existing(child.pid,fixture=True);stopped=existing(child.pid,stop=True,fixture=True)
        time.sleep(.3);frozen=existing(child.pid,fixture=True)
        stop_verified=stopped['phase']==3 and frozen['captured']==stopped['captured'] and frozen['calls']==stopped['calls']
        start(child.pid,True);time.sleep(1.5)
        second=existing(child.pid,fixture=True);final=existing(child.pid,stop=True,fixture=True)
        output,error=child.communicate(timeout=20)
        final.update(stop_verified=stop_verified,rearm_verified=second['captured']>first['captured'],
                     post_parse_capture_verified=bool(first['samples']),last_error_and_return_verified=child.returncode==0,
                     fixture_exit_code=child.returncode,fixture_result=output.strip(),fixture_stderr=error[:300])
        final['passed']=stop_verified and final['rearm_verified'] and final['post_parse_capture_verified'] and child.returncode==0 and \
            final['read_errors']==0 and final['calls']>final['succeeded']>final['room_matches']>=final['captured']>0 and \
            final['marker_matches']==0 and {s['content'] for s in first['samples']}=={'WXRECV1006','WRONG_MARKER'}
        save(final,'native-receiver-fixture.json');print(json.dumps(public(final)))
        return 0 if final['passed'] else 1
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=5)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    target=parser.add_mutually_exclusive_group(required=True);target.add_argument('--pid',type=int);target.add_argument('--fixture',action='store_true')
    action=parser.add_mutually_exclusive_group();action.add_argument('--status',action='store_true');action.add_argument('--stop',action='store_true');action.add_argument('--watch-status',action='store_true')
    args=parser.parse_args()
    if args.fixture:
        if args.status or args.stop or args.watch_status:raise ValueError('Fixture cannot use process actions')
        return fixture()
    if args.watch_status:watch(args.pid);return 0
    report=existing(args.pid,args.stop) if args.status or args.stop else start(args.pid)
    if not args.status:save(report)
    print(json.dumps(public(report)));return 0
if __name__=='__main__':sys.exit(main())
