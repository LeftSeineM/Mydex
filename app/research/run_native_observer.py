"""Native observer with continuous, status and explicit stop commands.

Only the pinned observer DLL and pinned client build are accepted. Test mode
starts its own fixture. No credential access, arbitrary DLL loading, or sends.
"""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import lief

from external_reader import Reader
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from probe_native import CLIENT, EXPECTED_SHA256
DIRECTORY=Path(configured_path('runtime', 'research-tools/native-observer'))
DLL=DIRECTORY/'wx-native-observer-v6.dll'
TARGET_RVA=0x17f3750
FIXTURE=DIRECTORY/'wx-native-fixture.exe'

class Config(C.Structure):
    _fields_=[('magic',W.DWORD),('seconds',W.DWORD),('fixture',W.DWORD),('reserved',W.DWORD),('marker',C.c_char*64)]
class State(C.Structure):
    _fields_=[('magic',W.DWORD),('phase',W.LONG),('calls',C.c_int64),('matches',C.c_int64),
              ('read_errors',C.c_int64),('vtable_rva',C.c_uint64),('thread_id',W.DWORD),
              ('room_ready',W.LONG),('room',C.c_char*128)]
class Shape(C.Structure):
    _fields_=[('ready',W.LONG),('hits',W.LONG),('root_vtable_rva',C.c_uint64),
              ('child8_vtable_rva',C.c_uint64),('child18_vtable_rva',C.c_uint64)]
class TextDiagnostic(C.Structure):
    _fields_=[('ready',W.LONG),('hits',W.LONG),('type_value',W.DWORD),('stage',W.DWORD),
              ('body_length',C.c_uint64),('body_capacity',C.c_uint64),('room_length',C.c_uint64),
              ('room_capacity',C.c_uint64),('body_exact',W.DWORD),('room_kind',W.DWORD)]

class NativeControl(Reader):
    ACCESS=Reader.ACCESS|0x2|0x8|0x20 # CREATE_THREAD, VM_OPERATION, VM_WRITE
    def __init__(self,pid):
        super().__init__(pid)
        signatures={
            'VirtualAllocEx':([W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD,W.DWORD],C.c_void_p),
            'VirtualFreeEx':([W.HANDLE,C.c_void_p,C.c_size_t,W.DWORD],W.BOOL),
            'WriteProcessMemory':([W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],W.BOOL),
            'CreateRemoteThread':([W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)],W.HANDLE),
            'WaitForSingleObject':([W.HANDLE,W.DWORD],W.DWORD),
            'GetExitCodeThread':([W.HANDLE,C.POINTER(W.DWORD)],W.BOOL),
            'GetModuleHandleW':([W.LPCWSTR],W.HMODULE),
            'GetProcAddress':([W.HMODULE,C.c_char_p],C.c_void_p),
            'GetModuleHandleExW':([W.DWORD,C.c_void_p,C.POINTER(W.HMODULE)],W.BOOL),
            'GetModuleFileNameW':([W.HMODULE,W.LPWSTR,W.DWORD],W.DWORD),
        }
        for name,(args,result) in signatures.items():
            function=getattr(self.k,name);function.argtypes=args;function.restype=result
    def run(self,address,parameter,timeout):
        """Write only a newly allocated parameter block, then call a fixed export."""
        size=len(parameter)
        allocation=self.k.VirtualAllocEx(self.handle,None,size,0x3000,0x04)
        if not allocation:raise C.WinError(C.get_last_error())
        thread=None;finished=False
        try:
            buf=C.create_string_buffer(parameter);copied=C.c_size_t()
            if not self.k.WriteProcessMemory(self.handle,allocation,buf,size,C.byref(copied)) or copied.value!=size:
                raise C.WinError(C.get_last_error())
            thread=self.k.CreateRemoteThread(self.handle,None,0,address,allocation,0,None)
            if not thread:raise C.WinError(C.get_last_error())
            if self.k.WaitForSingleObject(thread,timeout)!=0:
                raise TimeoutError('Thread still running; parameter allocation retained, no forced termination')
            finished=True;code=W.DWORD()
            if not self.k.GetExitCodeThread(thread,C.byref(code)):raise C.WinError(C.get_last_error())
            return code.value
        finally:
            if thread:self.k.CloseHandle(thread)
            if not thread or finished:self.k.VirtualFreeEx(self.handle,allocation,0,0x8000)
    def loader_address(self):
        local=self.k.GetProcAddress(self.k.GetModuleHandleW('kernel32.dll'),b'LoadLibraryW')
        owner=W.HMODULE()
        if not local or not self.k.GetModuleHandleExW(0x4|0x2,local,C.byref(owner)):
            raise C.WinError(C.get_last_error())
        path=C.create_unicode_buffer(32768)
        if not self.k.GetModuleFileNameW(owner,path,len(path)):raise C.WinError(C.get_last_error())
        base,_=self.module(Path(path.value));remote=base+local-owner.value
        if self.read(remote,24)!=C.string_at(local,24):raise ValueError('Loader entry mismatch')
        return remote

def verified_build():
    manifest=json.loads((DIRECTORY/'build.json').read_text())
    for name,digest in manifest['artifacts'].items():
        if hashlib.sha256((DIRECTORY/name).read_bytes()).hexdigest()!=digest:raise ValueError('Build changed')
    for name in ('native_observer.c','native_observer.h','native_fixture.c'):
        if hashlib.sha256((ROOT/'research'/name).read_bytes()).hexdigest()!=manifest['sources'][name]:
            raise ValueError('Source and binary differ; rebuild required')
    return manifest

def snapshot(process,pid,base,exports,manifest,fixture=False):
    state=State.from_buffer_copy(process.read(base+exports['lab_state'],C.sizeof(State)))
    if state.magic!=0x574c4231:raise ValueError('Invalid state version')
    report={'at':datetime.now(timezone.utc).isoformat(),'pid':pid,'fixture':fixture,
            'phase':state.phase,'running':state.phase==2,'calls':state.calls,'matches':state.matches,'target_rva':hex(TARGET_RVA),
            'observer_sha256':manifest['artifacts'][DLL.name],
            'read_errors':state.read_errors,'room_name_verified':False,'sending_enabled':False,
            'observer_dll_pinned_until_process_exit':True}
    if state.room_ready:
        report.update(room_id_candidate=bytes(state.room).decode('ascii'),vtable_rva=hex(state.vtable_rva),thread_id=state.thread_id)
    shapes=(Shape*16).from_buffer_copy(process.read(base+exports['lab_shapes'],C.sizeof(Shape)*16))
    report['object_shapes']=[{'hits':s.hits,'root_vtable_rva':hex(s.root_vtable_rva),
                             'child8_vtable_rva':hex(s.child8_vtable_rva),'child18_vtable_rva':hex(s.child18_vtable_rva)}
                            for s in shapes if s.ready==1]
    diagnostics=(TextDiagnostic*16).from_buffer_copy(process.read(base+exports['lab_text_diagnostics'],C.sizeof(TextDiagnostic)*16))
    report['text_diagnostics']=[{key:getattr(d,key) for key,_ in TextDiagnostic._fields_ if key!='ready'} for d in diagnostics if d.ready==1]
    return report

def existing(pid,stop=False,fixture=False):
    manifest=verified_build()
    pe=lief.PE.parse(str(DLL))
    exports={entry.name:entry.address for entry in pe.get_export().entries}
    with (NativeControl(pid) if stop else Reader(pid)) as process:
        expected=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=expected.resolve():raise ValueError('Unexpected target image')
        base,_=process.module(DLL) # Never loads anything for status/stop.
        code=process.run(base+exports['StopProbe'],b'\0',10000) if stop else None
        report=snapshot(process,pid,base,exports,manifest,fixture)
        if stop:
            report['return_code']=code
            if code or report['phase']!=3:raise RuntimeError('Observer did not stop cleanly')
        return report

def save_report(report,name='native-observer.json'):
    path=ROOT/'.local'/name
    temp=path.with_name(path.name+f'.{os.getpid()}.tmp')
    temp.write_text(json.dumps(report,indent=2),encoding='utf-8')
    temp.replace(path)

def watch_status(pid):
    """Local collector only: no scheduling, injection, or automatic reconnection."""
    import msvcrt
    lock=open(ROOT/'.local'/f'native-watch-{pid}.lock','a+b')
    lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:raise RuntimeError('A status collector already exists for this process')
    previous=None
    try:
        while True:
            try:report=existing(pid)
            except (OSError,ValueError) as exc:
                report={'at':datetime.now(timezone.utc).isoformat(),'pid':pid,'running':False,
                        'phase':'unavailable','error':type(exc).__name__,'sending_enabled':False}
            report['collector']='continuous';report['expires_at']=None
            save_report(report)
            key=(report['phase'],report.get('calls'),report.get('matches'),report.get('read_errors'))
            if key!=previous:
                # Counters and state changes only; no group identifiers in event log.
                public={k:v for k,v in report.items() if k not in ('room_id_candidate','thread_id')}
                with (ROOT/'.local/native-observer-events.jsonl').open('a',encoding='utf-8') as log:
                    log.write(json.dumps(public)+'\n')
                previous=key
            if not report['running']:return 0
            time.sleep(2)
    finally:
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()

def observe(pid,marker,seconds,fixture=False):
    manifest=verified_build()
    if not fixture:
        proof=json.loads((ROOT/'.local/native-observer-fixture.json').read_text())
        if not proof.get('passed') or proof.get('observer_sha256')!=manifest['artifacts'][DLL.name]:
            raise ValueError('This observer build has not passed the complete fixture test')
        if seconds==0 and not proof.get('continuous_stop_verified'):
            raise ValueError('Continuous operation and manual stop have not been tested')
    if not fixture and hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:
        raise ValueError('Unsupported client build')
    pe=lief.PE.parse(str(DLL)) # LIEF entries borrow their parent's storage.
    exports={entry.name:entry.address for entry in pe.get_export().entries}
    if not {'RunProbe','StopProbe','lab_state','lab_shapes','lab_text_diagnostics'}<=exports.keys():raise ValueError('Required exports missing')
    with NativeControl(pid) as process:
        expected=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=expected.resolve():raise ValueError('Unexpected target image')
        if not fixture:
            base,_=process.module(CLIENT)
            profile=json.loads((ROOT/'.local/abi/profile.json').read_text())
            fn=next(f for f in profile['functions'] if f['rva']==hex(TARGET_RVA))
            if profile['client_sha256']!=EXPECTED_SHA256 or process.read(base+TARGET_RVA,24)!=bytes.fromhex(fn['entry_bytes']):
                raise ValueError('Runtime entry mismatch')
        try:process.module(DLL)
        except ValueError:
            process.run(process.loader_address(),(str(DLL)+'\0').encode('utf-16-le'),10000)
        base,_=process.module(DLL)
        before=State.from_buffer_copy(process.read(base+exports['lab_state'],C.sizeof(State)))
        if before.phase not in (0,3):raise ValueError('Observer already running or previously failed')
        config=Config(0x574c4231,seconds,int(fixture),0,marker.encode('utf-8'))
        print(json.dumps({'phase':'observing','pid':pid,'seconds':seconds,'fixture':fixture}),flush=True)
        code=process.run(base+exports['RunProbe'],bytes(config),(seconds+10)*1000)
        report=snapshot(process,pid,base,exports,manifest,fixture)
        report.update(return_code=code,calls_this_run=report['calls']-before.calls,
                      matches_this_run=report['matches']-before.matches,mode='continuous' if seconds==0 else 'timed',
                      expires_at=None if seconds==0 else report['at'])
        return report

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    target=parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--pid',type=int);target.add_argument('--fixture',action='store_true')
    parser.add_argument('--marker',default='WXPAIR1006')
    parser.add_argument('--seconds',type=int,default=30,choices=range(1,121))
    action=parser.add_mutually_exclusive_group()
    action.add_argument('--continuous',action='store_true')
    action.add_argument('--stop',action='store_true')
    action.add_argument('--status',action='store_true')
    action.add_argument('--watch-status',action='store_true')
    args=parser.parse_args()
    if args.fixture and (args.stop or args.status or args.watch_status):raise ValueError('Use --pid for existing processes')
    if args.watch_status:return watch_status(args.pid)
    if args.stop or args.status:
        report=existing(args.pid,stop=args.stop)
        if args.stop:save_report(report)
        print(json.dumps({k:v for k,v in report.items() if k!='room_id_candidate'}));return 0
    if not 4<=len(args.marker.encode('utf-8'))<=63 or '\0' in args.marker:raise ValueError('Invalid marker')
    child=None
    try:
        if args.fixture:
            if args.seconds>5:raise ValueError('Fixture observation must be at most 5 seconds')
            verified_build()
            child=subprocess.Popen([str(FIXTURE),'--remote'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   text=True,creationflags=subprocess.CREATE_NO_WINDOW)
            if child.stdout.readline().strip()!='ready':raise RuntimeError('Fixture did not start')
            args.pid=child.pid
        report=observe(args.pid,args.marker,0 if args.continuous else args.seconds,args.fixture)
        if child:
            continuous_passed=False
            if args.continuous:
                time.sleep(2)
                active=existing(args.pid,fixture=True)
                stopped=existing(args.pid,stop=True,fixture=True)
                after=existing(args.pid,fixture=True)
                continuous_passed=active['running'] and active['calls']>0 and not stopped['running'] and after['phase']==3
            first_report=report
            report=observe(args.pid,args.marker,args.seconds,True)
            report['rearm_verified']=report['calls_this_run']>0 and report['matches_this_run']>0
            report['continuous_stop_verified']=continuous_passed
            report['first_run_calls']=first_report['calls_this_run']
            output,error=child.communicate(timeout=25)
            report.update(fixture_exit_code=child.returncode,fixture_result=output.strip(),fixture_stderr=error[:300])
            report['shape_capture_verified']=len(report['object_shapes'])>=2 and {d['stage'] for d in report['text_diagnostics']}=={2,4}
            report['passed']=child.returncode==0 and report['return_code']==0 and report['phase']==3 and report['matches']>0 and report['calls']>report['matches'] and report['read_errors']==0 and report['rearm_verified'] and report['shape_capture_verified'] and (continuous_passed if args.continuous else True)
        save_report(report,'native-observer-fixture.json' if child else 'native-observer.json')
        print(json.dumps({k:v for k,v in report.items() if k!='room_id_candidate'}),flush=True)
        return 0 if report.get('passed',report['return_code']==0 and report['phase']==(2 if args.continuous else 3)) else 1
    finally:
        if child and child.poll() is None:
            child.terminate();child.wait(timeout=5) # only the child this launcher created

if __name__=='__main__':sys.exit(main())
