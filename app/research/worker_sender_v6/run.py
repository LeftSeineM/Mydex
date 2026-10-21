"""Pinned group-only sender. Remote calls only queue; the client worker sends."""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import lief

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
from run_native_observer import NativeControl, CLIENT, EXPECTED_SHA256
from external_reader import Reader
from run_native_sender import Config, State

DIR = ROOT.parent/'native/worker-sender-v6'
DLL = DIR/'wx-worker-sender-v6.dll'
FIXTURE = DIR/'wx-send-fixture.exe'
PROOF = ROOT/'.local/account-sender-fixture.json'
TEST_TEXT = '小研：群助手自动发送测试1007，收到这条消息就说明回发成功。'

class WorkerState(C.Structure):
    _fields_ = [('magic', W.DWORD), ('phase', W.LONG), ('pending', W.LONG),
                ('worker_thread', W.DWORD), ('core_calls', C.c_int64),
                ('pump_calls', C.c_int64), ('queued', C.c_int64),
                ('executed', C.c_int64), ('context_failures', C.c_int64),
                ('last_code', W.DWORD), ('execution_thread', W.DWORD)]

def verified(fixture):
    manifest = json.loads((DIR/'build.json').read_text())
    for name, digest in manifest['artifacts'].items():
        if hashlib.sha256((DIR/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Binary differs from manifest')
    for name, digest in manifest['sources'].items():
        if hashlib.sha256((HERE/name).read_bytes()).hexdigest() != digest:
            raise ValueError('Source differs from binary')
    if not fixture:
        proof = json.loads(PROOF.read_text())
        if not proof.get('passed') or proof.get('sender_sha256') != manifest['artifacts'][DLL.name]:
            raise ValueError('This worker sender has not passed its fixture')
        if hashlib.sha256(CLIENT.read_bytes()).hexdigest() != EXPECTED_SHA256:
            raise ValueError('Client version changed')
    return manifest

def config(body, fixture, room=None, data=None):
    if fixture:
        room = room or '123456@chatroom'
        if room not in ('123456@chatroom','654321@chatroom','777777@chatroom','888888@chatroom','wxid_fixture_peer'): raise ValueError('Wrong fixture peer')
    else:
        data = Path(data) if data is not None else ROOT/'.local'
        binding = json.loads((data/'group-binding.json').read_text(encoding='utf-8'))
        session = json.loads((data/'session.json').read_text(encoding='utf-8'))
        if not binding.get('group_name_verified') or binding['room_id'] != session['allowed_room']:
            raise ValueError('Target group is not verified')
        room = room or binding['room_id']
        sys.path.insert(0,str(ROOT))
        from account_scope import validate_recipient
        validate_recipient(data,room)
    encoded = body.encode('utf-8')
    if not 1 <= len(encoded) <= 3072 or b'\0' in encoded:
        raise ValueError('Invalid text size')
    return Config(0x57535031, int(fixture), room.encode('ascii'), encoded)

def snapshot(process, pid, base, exports, manifest, fixture):
    worker = WorkerState.from_buffer_copy(process.read(base+exports['worker_state'], C.sizeof(WorkerState)))
    sender = State.from_buffer_copy(process.read(base+exports['send_state'], C.sizeof(State)))
    if worker.magic != 0x57535031 or sender.magic != worker.magic:
        raise ValueError('State layout mismatch')
    report = {name: getattr(worker, name) for name, _ in WorkerState._fields_ if name != 'magic'}
    report['sender'] = {name: getattr(sender, name) for name, _ in State._fields_ if name != 'magic'}
    report.update(at=datetime.now(timezone.utc).isoformat(), pid=pid, fixture=fixture,
                  sender_sha256=manifest['artifacts'][DLL.name], native_delivery_verified=False)
    return report

def action(pid, command, body=TEST_TEXT, fixture=False, room=None, adopt_thread=None, data=None):
    manifest = verified(fixture)
    pe = lief.PE.parse(str(DLL))
    exports = {entry.name: entry.address for entry in pe.get_export().entries}
    with (Reader(pid) if command == 'status' else NativeControl(pid)) as process:
        expected = FIXTURE if fixture else CLIENT.parent.parent/'Weixin.exe'
        if process.image_path().resolve() != expected.resolve():
            raise ValueError('Unexpected process image')
        try:
            base, _ = process.module(DLL)
        except ValueError:
            if command != 'install':
                raise ValueError('Install worker first')
            process.run(process.loader_address(), (str(DLL)+'\0').encode('utf-16-le'), 10000)
            base, _ = process.module(DLL)
        code = None
        if command in ('install', 'send'):
            cfg = config(body, fixture, room, data)
            if command=='send' or not fixture:
                registered=process.run(base+exports['RegisterPeer'],bytes(cfg),10000)
                if registered:raise ValueError('Recipient registration failed')
            name = 'InstallWorker' if command == 'install' else 'RunSend'
            code = process.run(base+exports[name], bytes(cfg), 10000)
        elif command == 'adopt':
            if not isinstance(adopt_thread,int) or adopt_thread<=0:raise ValueError('Missing proven worker thread')
            code=process.run(base+exports['AdoptWorker'],bytes((W.DWORD*2)(0x57535031,adopt_thread)),10000)
        elif command == 'stop':
            code = process.run(base+exports['StopWorker'], b'\0', 10000)
        elif command != 'status':
            raise ValueError('Unknown action')
        report = snapshot(process, pid, base, exports, manifest, fixture)
        report['return_code'] = code
        return report

def wait_for(pid, count):
    end = time.monotonic()+3
    while time.monotonic() < end:
        report = action(pid, 'status', fixture=True)
        if report['executed'] >= count and report['sender']['disposed'] >= count:
            return report
        time.sleep(.05)
    raise TimeoutError('Worker did not execute queued fixture item')

def fixture_test():
    child = subprocess.Popen([str(FIXTURE)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        if child.stdout.readline().strip() != 'ready':
            raise ValueError('Fixture not ready')
        installed = action(child.pid, 'install', fixture=True)
        one_queue = action(child.pid, 'send', 'WXC1007OK', True)
        one = wait_for(child.pid, 1)
        two_queue = action(child.pid, 'send', TEST_TEXT, True, room='654321@chatroom')
        two = wait_for(child.pid, 2)
        three_queue = action(child.pid, 'send', TEST_TEXT, True, room='777777@chatroom')
        three = wait_for(child.pid, 3)
        four_queue = action(child.pid, 'send', TEST_TEXT, True, room='888888@chatroom')
        four = wait_for(child.pid, 4)
        private_queue = action(child.pid, 'send', 'PRIVATE_FIXTURE', True, room='wxid_fixture_peer')
        private = wait_for(child.pid, 5)
        stopped = action(child.pid, 'stop', fixture=True)
        rejected = action(child.pid, 'send', 'NoSendAfterStop', True)
        time.sleep(.2)
        after = action(child.pid, 'status', fixture=True)
        output, error = child.communicate(timeout=8)
        passed = (not installed['return_code'] and installed['phase'] == 2
                  and not one_queue['return_code'] and not two_queue['return_code']
                  and one['sender']['callbacks'] == 1 and two['sender']['callbacks'] == 2
                  and two['worker_thread'] != 0 and two['worker_thread'] == two['execution_thread']
                  and two['execution_thread'] == two['sender']['thread_id']
                  and two['context_failures'] == 0 and two['last_code'] == 0
                  and two['sender']['disposed'] == 2 and not three_queue['return_code']
                  and three['sender']['callbacks'] == 3 and three['sender']['disposed'] == 3
                  and three['execution_thread'] == three['worker_thread']
                  and three['context_failures'] == 0 and not four_queue['return_code']
                  and four['sender']['callbacks'] == 4 and four['sender']['disposed'] == 4
                  and four['context_failures'] == 0 and not stopped['return_code']
                  and not private_queue['return_code'] and private['sender']['callbacks']==5
                  and private['sender']['disposed']==5 and private['context_failures']==0
                  and stopped['phase'] == 5 and rejected['return_code'] == 11
                  and after['core_calls'] == stopped['core_calls']
                  and after['pump_calls'] == stopped['pump_calls'] and child.returncode == 0)
        report = dict(private, private_fixture_verified=passed, passed=passed, fixture_exit_code=child.returncode,
                      fixture_result=output.strip(), fixture_stderr=error[:200],
                      worker_context_verified=passed, stop_verified=passed, second_group_verified=passed, third_group_verified=passed, fourth_group_verified=passed)
        PROOF.write_text(json.dumps(report, indent=2), encoding='utf-8')
        return report
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--pid', type=int)
    parser.add_argument('--action', choices=['install', 'send', 'status', 'stop','adopt'], default='status')
    parser.add_argument('--text', default=TEST_TEXT)
    parser.add_argument('--room')
    parser.add_argument('--adopt-thread',type=int)
    args = parser.parse_args()
    report = fixture_test() if args.fixture else action(args.pid, args.action, args.text,room=args.room,adopt_thread=args.adopt_thread)
    if not args.fixture:
        (ROOT/'.local/worker-sender.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))
    raise SystemExit(0 if report.get('passed', report.get('return_code') in (None, 0)) else 1)
