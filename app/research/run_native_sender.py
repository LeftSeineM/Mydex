"""Fixed-version, bound-group text send. A native return is not delivery proof."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse,ctypes as C
from ctypes import wintypes as W
from datetime import datetime,timezone
import hashlib,json,subprocess,time
from pathlib import Path
import lief
from run_native_observer import NativeControl,CLIENT,EXPECTED_SHA256,ROOT
from external_reader import Reader
DIR=Path(configured_path('runtime', 'research-tools/native-sender'))
DLL=DIR/'wx-native-sender-v1.dll';FIXTURE=DIR/'wx-send-fixture.exe'
class Config(C.Structure):_fields_=[('magic',W.DWORD),('fixture',W.DWORD),('room',C.c_char*128),('body',C.c_char*4096)]
class State(C.Structure):_fields_=[('magic',W.DWORD),('phase',W.LONG),('submissions',C.c_int64),('callbacks',C.c_int64),('disposed',C.c_int64),('callback_tag',W.DWORD),('thread_id',W.DWORD)]
def build():
    manifest=json.loads((DIR/'build.json').read_text())
    for name,digest in manifest['artifacts'].items():
        if hashlib.sha256((DIR/name).read_bytes()).hexdigest()!=digest:raise ValueError('Sender build mismatch')
    for name,digest in manifest['sources'].items():
        if hashlib.sha256((ROOT/'research'/name).read_bytes()).hexdigest()!=digest:raise ValueError('Sender source mismatch')
    return manifest
def send(pid,body,fixture=False):
    manifest=build();pe=lief.PE.parse(str(DLL));exports={e.name:e.address for e in pe.get_export().entries}
    if not fixture:
        raise RuntimeError('Live sender disabled: first client call coincided with a crash; ABI/thread path requires offline repair')
    if not fixture:
        proof=json.loads((ROOT/'.local/native-sender-fixture.json').read_text())
        if not proof.get('passed') or proof['sender_sha256']!=manifest['artifacts'][DLL.name]:raise ValueError('Fixture not verified')
        if hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:raise ValueError('Unsupported client build')
        binding=json.loads((ROOT/'.local/group-binding.json').read_text(encoding='utf-8'))
        if not binding.get('group_name_verified'):raise ValueError('Group not verified')
        room=binding['room_id']
    else:room='123456@chatroom'
    encoded=body.encode('utf-8')
    if not 1<=len(encoded)<=3072:raise ValueError('Body too large')
    with NativeControl(pid) as process:
        expected=FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve()!=expected.resolve():raise ValueError('Unexpected process')
        try:base,_=process.module(DLL)
        except ValueError:
            process.run(process.loader_address(),(str(DLL)+'\0').encode('utf-16-le'),10000)
            base,_=process.module(DLL)
        code=process.run(base+exports['RunSend'],bytes(Config(0x57535031,int(fixture),room.encode('ascii'),encoded)),15000)
        time.sleep(.3)
        state=State.from_buffer_copy(process.read(base+exports['send_state'],C.sizeof(State)))
        report={name:getattr(state,name) for name,_ in State._fields_ if name not in ('magic','thread_id')}
        report.update(at=datetime.now(timezone.utc).isoformat(),pid=pid,fixture=fixture,return_code=code,
                      sender_sha256=manifest['artifacts'][DLL.name],native_delivery_verified=False)
        return report
def fixture():
    child=subprocess.Popen([str(FIXTURE)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        if child.stdout.readline().strip()!='ready':raise ValueError('Fixture not ready')
        one=send(child.pid,'WXC1007OK',True)
        two=send(child.pid,'小研：这是一条较长的群助手原生接口测试。',True)
        output,error=child.communicate(timeout=8)
        two.update(fixture_result=output.strip(),fixture_exit_code=child.returncode,fixture_stderr=error[:160],
                   synchronous_callback_verified=one['callbacks']==1 and one['disposed']==1,
                   delayed_callback_verified=two['callbacks']==2 and two['disposed']==2)
        two['passed']=not one['return_code'] and not two['return_code'] and two['callbacks']==2 and two['disposed']==2 and child.returncode==0
        (ROOT/'.local/native-sender-fixture.json').write_text(json.dumps(two,indent=2),encoding='utf-8');return two
    finally:
        if child.poll() is None:child.terminate();child.wait(timeout=5)
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--fixture',action='store_true');parser.add_argument('--pid',type=int)
    parser.add_argument('--text',default='WXC1007OK')
    args=parser.parse_args()
    report=fixture() if args.fixture else send(args.pid,args.text)
    if not args.fixture:(ROOT/'.local/native-send-result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report));raise SystemExit(0 if not report['return_code'] else 1)
