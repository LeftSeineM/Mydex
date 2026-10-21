"""Locate only an explicitly supplied test marker using an external read handle.

Only matching text objects can expose their recipient ID; unrelated messages
are neither decoded nor saved. No code is installed into the inspected client.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from probe_native import CLIENT,EXPECTED_SHA256
from external_reader import Reader

def msvc_bytes(reader,address,maximum,expected_length=None):
    header=reader.read(address,32)
    size,capacity=struct.unpack_from('<QQ',header,16)
    if expected_length is not None and size!=expected_length:return None
    if size>maximum or capacity<size or capacity>1048576:return None
    if capacity<16:
        if size>15:return None
        return header[:size]
    pointer=struct.unpack_from('<Q',header)[0]
    if pointer<65536:return None
    return reader.read(pointer,size) if size else b''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',required=True,type=int)
    parser.add_argument('--marker',default='探针测试')
    parser.add_argument('--mib',type=int,default=1024,choices=range(1,2049))
    parser.add_argument('--seconds',type=int,default=30,choices=range(1,61))
    parser.add_argument('--watch',type=int,default=0,choices=range(0,181),help='repeat bounded scans for at most this many seconds')
    args=parser.parse_args();marker=args.marker.encode('utf-8')
    if not 4<=len(marker)<=128:raise ValueError('Use a distinct 4–128 byte test marker')
    if hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:raise ValueError('Client build changed')
    report={'started_at':datetime.now(timezone.utc).isoformat(),'mode':'external_vm_read_only',
            'pid':args.pid,'client_sha256':EXPECTED_SHA256,'injects_code':False,'writes_client_memory':False,
            'scanned_bytes':0,'read_errors':0,'vtable_matches':0,'matches':[],
            'raw_marker_counts':{'utf8':0,'utf16le':0},'marker_locations':[]}
    deadline=time.monotonic()+args.seconds;budget=args.mib*1048576;seen=set()
    raw_seen=set();encodings={'utf8':marker,'utf16le':args.marker.encode('utf-16-le')}
    overlap=max(32,max(len(value) for value in encodings.values()))
    with Reader(args.pid) as reader:
        if reader.image_path().resolve()!=(CLIENT.parent.parent/'Weixin.exe').resolve():raise ValueError('Unexpected process')
        base,size=reader.module(CLIENT)
        profile=json.loads((ROOT/'.local/abi/profile.json').read_text())
        if profile['client_sha256']!=EXPECTED_SHA256:raise ValueError('Stale evidence profile')
        factory=next(f for f in profile['functions'] if f['rva']=='0x6f4c70')
        if reader.read(base+0x6f4c70,24)!=bytes.fromhex(factory['entry_bytes']):raise ValueError('Runtime code differs')
        needle=struct.pack('<Q',base+0x8e53588)
        for start,length in reader.regions():
            for offset in range(0,length,1048576-overlap):
                if time.monotonic()>=deadline or report['scanned_bytes']>=budget:break
                count=min(1048576,length-offset,budget-report['scanned_bytes'])
                try:block=reader.read(start+offset,count)
                except OSError:report['read_errors']+=1;report['scanned_bytes']+=count;continue
                report['scanned_bytes']+=count;cursor=0
                for encoding,exact_bytes in encodings.items():
                    raw_cursor=0
                    while True:
                        raw_pos=block.find(exact_bytes,raw_cursor)
                        if raw_pos<0:break
                        raw_cursor=raw_pos+1;raw_address=start+offset+raw_pos
                        if (encoding,raw_address) in raw_seen:continue
                        raw_seen.add((encoding,raw_address));report['raw_marker_counts'][encoding]+=1
                        if len(report['marker_locations'])<64:
                            report['marker_locations'].append({'encoding':encoding,'address':hex(raw_address)})
                while True:
                    pos=block.find(needle,cursor)
                    if pos<0:break
                    cursor=pos+1;address=start+offset+pos
                    if address%8 or address in seen:continue
                    seen.add(address);report['vtable_matches']+=1
                    try:
                        if struct.unpack('<I',reader.read(address+0x118,4))[0]!=1:continue
                        body=msvc_bytes(reader,address+0x758,128,len(marker))
                        if body!=marker:continue
                        room=msvc_bytes(reader,address+0xb0,128)
                        if not room or not room.endswith(b'@chatroom'):continue
                        if reader.read(address,8)!=needle:continue
                        # Exact sample only. This is a candidate, not a room binding.
                        report['matches'].append({'room_id_candidate':room.decode('ascii'),
                            'object_address':hex(address),'marker_exact_match':True,'room_name_verified':False})
                    except (OSError,ValueError,UnicodeError):continue
                if len(marker)<=15:
                    cursor=0
                    while True:
                        pos=block.find(marker,cursor)
                        if pos<0:break
                        cursor=pos+1;string_address=start+offset+pos
                        if string_address%8:continue
                        try:
                            if msvc_bytes(reader,string_address,128,len(marker))!=marker:continue
                            address=string_address-0x758
                            if address in seen:continue
                            vptr=struct.unpack('<Q',reader.read(address,8))[0]
                            if not base<=vptr<base+size:continue
                            if struct.unpack('<I',reader.read(address+0x118,4))[0]!=1:continue
                            room=msvc_bytes(reader,address+0xb0,128)
                            if not room or not room.endswith(b'@chatroom'):continue
                            report['matches'].append({'room_id_candidate':room.decode('ascii'),
                                'object_address':hex(address),'vtable_rva':hex(vptr-base),
                                'marker_exact_match':True,'room_name_verified':False})
                            seen.add(address)
                        except (OSError,ValueError,UnicodeError):continue
                del block
            if time.monotonic()>=deadline or report['scanned_bytes']>=budget:break
        report['limit_reached']=report['scanned_bytes']>=budget or time.monotonic()>=deadline
    report['completed_at']=datetime.now(timezone.utc).isoformat()
    path=ROOT/'.local/external-marker.json';path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('matches','marker_locations')}|{'match_count':len(report['matches'])}))
    return 0

if __name__=='__main__':
    # The parent launches only this read-only scanner; each pass exits and closes
    # its read handle. Logs contain counts, never arbitrary message contents.
    if '--watch' in sys.argv and int(sys.argv[sys.argv.index('--watch')+1])>0:
        import subprocess
        index=sys.argv.index('--watch');duration=int(sys.argv[index+1])
        if not 1<=duration<=180:raise ValueError('Watch duration out of bounds')
        child_args=sys.argv[1:index]+sys.argv[index+2:]
        until=time.monotonic()+duration;found=False
        while time.monotonic()<until:
            result=subprocess.run([sys.executable,str(Path(__file__).resolve()),*child_args],check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,timeout=65)
            if result.returncode:sys.exit(result.returncode)
            report=json.loads((ROOT/'.local/external-marker.json').read_text())
            if report['matches']:found=True;break
            time.sleep(min(1,max(0,until-time.monotonic())))
        print(json.dumps({'watch_complete':True,'matched':found}),flush=True)
    else:sys.exit(main())
