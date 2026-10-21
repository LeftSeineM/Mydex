"""Exercise Frida only against the child fixture created by this test."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=Path(configured_path('runtime', 'research-tools/wx-lab-fixture.exe'))
sys.path.insert(0,str(FIXTURE.parent))
import frida

SCRIPT=r'''
if(Process.mainModule.name.toLowerCase()!=='wx-lab-fixture.exe')throw new Error('Not our fixture');
let count=0;
const hook=Interceptor.attach(Process.mainModule.getExportByName('probe_tick'),{onEnter(){count++;}});
rpc.exports={count(){return count;},stop(){hook.detach();Interceptor.flush();return count;}};
'''
SCAN_SCRIPT=r'''
if(Process.mainModule.name.toLowerCase()!=='wx-lab-fixture.exe')throw new Error('Not our fixture');
rpc.exports={check(){const p=Process.mainModule.getExportByName('fixture_marker');return p.readUtf8String(23);}};
'''


def test_case(mode):
    child=subprocess.Popen([str(FIXTURE),'30'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           text=True,creationflags=subprocess.CREATE_NO_WINDOW)
    if child.stdout.readline().strip()!='ready':raise RuntimeError('Fixture did not start')
    session=None;script=None;extra=None
    result={'mode':mode,'pid':child.pid,'cycles':[]}
    try:
        session=frida.get_local_device().attach(child.pid)
        for cycle in range(4):
            if mode=='production_timer':
                # Reuse the probe's actual timers, counters and teardown on our
                # own exported function. No client PID or client DLL is used.
                sys.path.insert(0,str(ROOT))
                from probe_native import AGENT
                import lief
                pe=lief.PE.parse(str(FIXTURE))
                target=next(e.address for e in pe.get_export().entries if e.name=='probe_tick')
                section=next(s for s in pe.sections if s.virtual_address<=target<s.virtual_address+s.sizeof_raw_data)
                offset=section.pointerto_raw_data+target-section.virtual_address
                config={'path':FIXTURE.as_posix(),'seconds':1,'targets':[{'name':'fixture_tick','rva':target,'bytes':FIXTURE.read_bytes()[offset:offset+24].hex()}]}
                source=AGENT.replace("Process.getModuleByName('Weixin.dll')","Process.getModuleByName('wx-lab-fixture.exe')").replace('CONFIG',json.dumps(config),1)
                done=threading.Event();events=[]
                def on_message(message,data):
                    event=message.get('payload',message);events.append(event)
                    if event.get('type') in ('finished','probe_error','error'):done.set()
                script=session.create_script(source);script.on('message',on_message);script.load()
                if not done.wait(5):raise AssertionError('Probe timer did not finish')
                finished=next((e for e in events if e.get('type')=='finished' and e.get('reason')=='time_limit'),None)
                if finished is None:raise AssertionError('Probe did not finish cleanly: '+str(events))
                count=finished['counts']['fixture_tick']
            else:
                script=session.create_script(SCRIPT);script.load();time.sleep(0.7)
            if mode=='second_session':
                extra=frida.get_local_device().attach(child.pid)
                scanner=extra.create_script(SCAN_SCRIPT);scanner.load()
                marker=scanner.exports_sync.check()
                if not marker.startswith('WX_LAB_OWN_FIXTURE_ONLY'):raise AssertionError('Marker mismatch')
                scanner.unload();extra.detach();extra=None
            stopped_count=script.exports_sync.stop()
            if mode!='production_timer':count=stopped_count
            script.unload();script=None
            result['cycles'].append({'cycle':cycle,'observed_calls':count})
            if count<=0:raise AssertionError('No observed calls')
            time.sleep(0.7)
        session.detach();session=None
        stdout,stderr=child.communicate(timeout=35)
        result.update(exit_code=child.returncode,fixture_output=stdout.strip(),stderr=stderr[:500],
                      passed=child.returncode==0)
    except Exception as exc:
        result.update(passed=False,error=type(exc).__name__+': '+str(exc)[:250],exit_code=child.poll())
    finally:
        if script:
            try:script.unload()
            except Exception:pass
        for s in (extra,session):
            if s:
                try:s.detach()
                except Exception:pass
        if child.poll() is None:
            # This is exclusively the process created above, never a discovered application PID.
            child.terminate();child.wait(timeout=5)
    print(json.dumps(result),flush=True)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('single_session','second_session','production_timer'),action='append')
    args=parser.parse_args()
    report={'started_at':datetime.now(timezone.utc).isoformat(),'frida_version':frida.__version__,
            'target':'own_fixture_only','wechat_touched':False,'cases':[]}
    for mode in args.mode or ('single_session','second_session','production_timer'):report['cases'].append(test_case(mode))
    report['completed_at']=datetime.now(timezone.utc).isoformat()
    name='fixture-instrumentation'+('-'+'-'.join(args.mode) if args.mode else '')+'.json'
    (ROOT/'.local'/name).write_text(json.dumps(report,indent=2),encoding='utf-8')
    sys.exit(0 if all(r['passed'] for r in report['cases']) else 1)
