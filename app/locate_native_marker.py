"""Locate only the user-confirmed test marker in private writable memory.

No process dumps, credential reads, send calls, or UI automation. Candidate
objects are not trusted as callable interfaces or as verified room bindings.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import threading
import time

from probe_native import CLIENT, EXPECTED_SHA256, ROOT, TOOLS, verify_process, require_client_probe_clearance

AGENT = r'''
const mod=Process.getModuleByName('Weixin.dll');
if (mod.path.replace(/\\/g,'/').toLowerCase() !== CLIENT_PATH.toLowerCase()) throw new Error('Module path mismatch');
const marker='探针测试';
const pattern='e6 8e a2 e9 92 88 e6 b5 8b e8 af 95';
const budget=1024*1024*1024;
const deadline=Date.now()+45000;
const chunk=1024*1024;
const ranges=Process.enumerateRanges({protection:'rw-',coalesce:true}).filter(r=>!r.file);
let scanned=0,matches=0,errors=0,cancelled=false,inlineMarkers=0;
const candidates=[];
function stringAt(address,max) {
  const len=address.add(16).readU64().toNumber();
  const capacity=address.add(24).readU64().toNumber();
  if (!Number.isSafeInteger(len)||!Number.isSafeInteger(capacity)||len<1||len>max||capacity<len||capacity>65536) return null;
  const data=capacity<16?address:address.readPointer();
  if(data.isNull())return null;
  return data.readUtf8String(len);
}
function consider(address) {
  try {
    if(address.add(16).readU64().toNumber()!==12 || address.add(24).readU64().toNumber()!==15)return;
    if(stringAt(address,12)!==marker)return;
    inlineMarkers++;
    for(let delta=-0x900;delta<=0x100;delta+=8) {
      try {
        const field=address.add(delta);
        const recipient=stringAt(field,128);
        if(!recipient || !/^[A-Za-z0-9_@.-]{1,128}$/.test(recipient) || !recipient.endsWith('@chatroom'))continue;
        const object=field.sub(0xb0);
        const vtable=object.readPointer();
        const type=object.add(0x118).readU32();
        candidates.push({marker_address:address.toString(),possible_object_address:object.toString(),
          candidate_content_offset:0xb0-delta,relative_recipient_offset:delta,assumed_recipient_offset:'0xb0',
          assumed_type_offset:'0x118',candidate_vtable_in_module:vtable.compare(mod.base)>=0&&vtable.compare(mod.base.add(mod.size))<0,
          room_id:recipient,marker,candidate_type:type,validated:false});
      } catch(e) { /* Unrelated/unreadable layouts are not dumped. */ }
    }
  } catch(e) { errors++; }
}
async function run() {
  send({type:'ready',mode:'exact_marker_search',range_count:ranges.length,max_bytes:budget});
  for(const range of ranges) {
    for(let offset=0;offset<range.size;offset+=chunk-32) {
      if(cancelled||Date.now()>deadline||scanned>=budget||matches>=256)break;
      const size=Math.min(chunk,range.size-offset,budget-scanned);
      if(size<12)break;
      try {
        await new Promise(resolve=>Memory.scan(range.base.add(offset),size,pattern,{
          onMatch(address){matches++;consider(address);if(matches>=256)return 'stop';},
          onError(){errors++;},onComplete(){resolve();}
        }));
      } catch(e){errors++;}
      scanned+=size;
    }
    if(cancelled||Date.now()>deadline||scanned>=budget||matches>=256)break;
  }
  send({type:'finished',scanned_bytes:scanned,marker_matches:matches,inline_marker_count:inlineMarkers,read_errors:errors,candidates,
    limit_reached:scanned>=budget||matches>=256||Date.now()>deadline});
}
rpc.exports={stop(){cancelled=true;}};
run().catch(e=>send({type:'error',message:String(e)}));
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    args=parser.parse_args()
    require_client_probe_clearance()
    verify_process(args.pid)
    if hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:
        raise ValueError('Unsupported Weixin build')
    sys.path.insert(0,str(TOOLS))
    import frida
    finished=threading.Event()
    report={'pid':args.pid,'started_at':datetime.now(timezone.utc).isoformat(),'mode':'exact_marker_search','events':[]}
    def on_message(message,data):
        event=message.get('payload',{'type':'error','message':message.get('description','unknown')})
        event={**event,'observed_at':datetime.now(timezone.utc).isoformat()}
        report['events'].append(event)
        summary={k:v for k,v in event.items() if k!='candidates'}
        if 'candidates' in event: summary['candidate_count']=len(event['candidates'])
        print(json.dumps(summary,ensure_ascii=False),flush=True)
        if event.get('type') in ('finished','error'):finished.set()
    session=None;script=None
    try:
        session=frida.get_local_device().attach(args.pid)
        script=session.create_script(AGENT.replace('CLIENT_PATH',json.dumps(CLIENT.as_posix()),1))
        script.on('message',on_message);script.load();finished.wait(55)
    except Exception as exc:
        report['error']=type(exc).__name__+': '+str(exc)[:200]
        print(json.dumps({'error':report['error']}),flush=True)
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
        path=ROOT/'.local/native-marker.json'
        path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if any(e.get('type')=='finished' for e in report['events']) else 2


if __name__=='__main__':sys.exit(main())
