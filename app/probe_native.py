"""Bounded native call-count probe. Does not read messages or invoke send functions.

Frida temporarily instruments the selected entry points in the user's Weixin
process. Disk hash, process path and runtime code bytes must match first.
"""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import sys
import threading
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
CLIENT = Path(configured_path('client', ''))
EXPECTED_SHA256 = '10f8e995453e2da46d4f2b5080cd6da1f13cc5147746adc119ceae38cb039de5'
TOOLS = Path(configured_path('runtime', 'research-tools'))


def require_client_probe_clearance():
    raise RuntimeError('客户端动态探针已停用：已确认 frida-agent.dll 崩溃，须先完成隔离复现和稳定性修复。')

AGENT = r'''
const config = CONFIG;
const hooks = [];
const counts = {};
let stopped = false;
function finish(reason) {
  if (stopped) return;
  stopped = true;
  for (const hook of hooks) hook.detach();
  Interceptor.flush();
  send({type:'finished', reason, counts});
}
try {
  if (Process.arch !== 'x64') throw new Error('Architecture mismatch');
  const mod = Process.getModuleByName('Weixin.dll');
  if (mod.path.replace(/\\/g,'/').toLowerCase() !== config.path.toLowerCase())
    throw new Error('Module path mismatch');
  for (const target of config.targets) {
    const address = mod.base.add(target.rva);
    const range = Process.findRangeByAddress(address);
    if (!range || !range.protection.includes('x')) throw new Error('Non-executable target');
    const bytes = Array.from(new Uint8Array(address.readByteArray(target.bytes.length/2)))
      .map(x=>x.toString(16).padStart(2,'0')).join('');
    if (bytes !== target.bytes) throw new Error('Runtime bytes mismatch: '+target.name);
  }
  for (const target of config.targets) {
    counts[target.name]=0;
    hooks.push(Interceptor.attach(mod.base.add(target.rva), {
      onEnter() { counts[target.name]++; }
    }));
  }
  Interceptor.flush();
  send({type:'ready', pid:Process.id, targets:config.targets.map(t=>t.name), duration:config.seconds});
  const timer=setInterval(()=>{if(!stopped)send({type:'counts',counts});},10000);
  setTimeout(()=>{clearInterval(timer);finish('time_limit');},config.seconds*1000);
  rpc.exports={stop(){finish('requested');}};
} catch(e) {
  finish('setup_failed');
  send({type:'probe_error',message:String(e)});
}
'''


def verify_process(pid):
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype=wintypes.BOOL
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.OpenProcess(0x1000,False,pid)
    if not handle: raise ctypes.WinError(ctypes.get_last_error())
    try:
        buf=ctypes.create_unicode_buffer(32768); size=wintypes.DWORD(len(buf))
        if not kernel.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(buf.value).resolve()!=CLIENT.parent.parent/'Weixin.exe':
            raise ValueError('PID is not the expected Weixin executable')
    finally: kernel.CloseHandle(handle)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--seconds',type=int,default=90,choices=range(10,601),metavar='10..600')
    args=parser.parse_args()
    require_client_probe_clearance()
    verify_process(args.pid)
    import lief
    content=CLIENT.read_bytes()
    if hashlib.sha256(content).hexdigest()!=EXPECTED_SHA256: raise ValueError('Unsupported Weixin build')
    pe=lief.PE.parse(str(CLIENT))
    targets=[]
    for name,rva in [('send_queue',0x179ce50),('send_stage_a',0x17f3750),('send_stage_b',0x17f7a00),('sync_request',0x2e324a0)]:
        section=next(s for s in pe.sections if s.virtual_address<=rva<s.virtual_address+s.sizeof_raw_data)
        offset=section.pointerto_raw_data+rva-section.virtual_address
        targets.append({'name':name,'rva':rva,'bytes':content[offset:offset+24].hex()})
    del content
    config={'path':CLIENT.as_posix(),'seconds':args.seconds,'targets':targets}
    sys.path.insert(0,str(TOOLS))
    import frida
    report={'client_sha256':EXPECTED_SHA256,'pid':args.pid,'frida_version':frida.__version__,
            'started_at':datetime.now(timezone.utc).isoformat(),
            'mode':'call_counts_only','reads_message_content':False,'sends_messages':False,'events':[]}
    done=threading.Event()
    def on_message(message,data):
        event=message.get('payload') if message.get('type')=='send' else {'type':'agent_error','message':message.get('description','unknown')}
        event={**event,'observed_at':datetime.now(timezone.utc).isoformat()}
        report['events'].append(event)
        print(json.dumps(event,ensure_ascii=False),flush=True)
        if event.get('type') in ('finished','probe_error','agent_error'): done.set()
    session=None; script=None
    try:
        session=frida.get_local_device().attach(args.pid)
        session.on('detached',lambda reason,*_: (report.update(detached_reason=reason),done.set()))
        script=session.create_script(AGENT.replace('CONFIG',json.dumps(config),1))
        script.on('message',on_message)
        script.load()
        done.wait(args.seconds+5)
    except Exception as exc:
        report['error']=type(exc).__name__+': '+str(exc)[:200]
        print(json.dumps({'type':'probe_error','message':report['error']}),flush=True)
    finally:
        if script:
            try: script.exports_sync.stop()
            except Exception: pass
            try: script.unload()
            except Exception: pass
        if session:
            try: session.detach()
            except Exception: pass
        report['completed_at']=datetime.now(timezone.utc).isoformat()
        payload=json.dumps(report,indent=2)
        stamp=report['started_at'].replace(':','').replace('+','_')
        (ROOT/'.local'/('native-probe-'+stamp+'.json')).write_text(payload,encoding='utf-8')
        (ROOT/'.local/native-probe.json').write_text(payload,encoding='utf-8')
    clean_finish=any(e.get('type')=='finished' and e.get('reason') in ('time_limit','requested') for e in report['events'])
    return 0 if clean_finish and not report.get('error') and report.get('detached_reason')!='process-terminated' else 2


if __name__=='__main__': sys.exit(main())
