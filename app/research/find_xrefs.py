"""On-disk reference candidates with full-function disassembly verification.

Never opens a process. A byte-pattern match is not an instruction until objdump
decodes the same reference from an unwind function boundary.
"""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from probe_native import CLIENT,EXPECTED_SHA256
import lief

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--rva',action='append',type=lambda x:int(x,0),default=[])
parser.add_argument('--text',action='append',default=[])
parser.add_argument('--literal-window',type=int,default=0,choices=range(0,65),metavar='0..64')
args=parser.parse_args()
data=CLIENT.read_bytes()
if hashlib.sha256(data).hexdigest()!=EXPECTED_SHA256:raise ValueError('Unsupported client build')
pe=lief.PE.parse(str(CLIENT));base=pe.optional_header.imagebase
targets={rva:{'rva':hex(rva),'label':'explicit_rva'} for rva in args.rva}
for term in args.text:
    needle=term.encode('utf-8');cursor=0
    while True:
        offset=data.find(needle,cursor)
        if offset<0:break
        cursor=offset+1
        section=next((s for s in pe.sections if s.pointerto_raw_data<=offset<s.pointerto_raw_data+s.sizeof_raw_data),None)
        if section:
            rva=section.virtual_address+offset-section.pointerto_raw_data
            for delta in range(-args.literal_window,args.literal_window+1):
                targets[rva+delta]={'rva':hex(rva+delta),'label':term,'literal_delta':delta}
pdata=next(s for s in pe.sections if s.name=='.pdata')
raw=data[pdata.pointerto_raw_data:pdata.pointerto_raw_data+pdata.sizeof_raw_data]
funcs=sorted((a,b) for a,b,_ in struct.iter_unpack('<III',raw[:len(raw)//12*12]) if a and b>a)
starts=[a for a,b in funcs];candidates=[]
for section in pe.sections:
    if not section.characteristics&0x20000000:continue
    raw=data[section.pointerto_raw_data:section.pointerto_raw_data+section.sizeof_raw_data]
    pattern=rb'(?:[\x48\x4c][\x8d\x8b]|\x0f[\x10\x28\x6f])[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]|\xe8'
    for match in re.finditer(pattern,raw):
        end=match.end()
        if end+4>len(raw):continue
        target=section.virtual_address+end+4+struct.unpack_from('<i',raw,end)[0]
        if target not in targets:continue
        source=section.virtual_address+match.start();i=bisect_right(starts,source)-1
        func=funcs[i] if i>=0 and source<funcs[i][1] else None
        candidates.append({'site_rva':hex(source),'target_rva':hex(target),'kind':'direct_call' if match.group()==b'\xe8' else 'rip_reference',
                           'function_rva':hex(func[0]) if func else None,'end_rva':hex(func[1]) if func else None,'instruction_verified':False})
out=ROOT/'.local/abi/xrefs';out.mkdir(exist_ok=True)
cache={}
for item in candidates:
    if not item['function_rva']:continue
    start=int(item['function_rva'],16);end=int(item['end_rva'],16)
    if start not in cache:
        asm=subprocess.run([configured_path('objdump', ''),'-d','-M','intel','--start-address='+hex(base+start),'--stop-address='+hex(base+end),str(CLIENT)],capture_output=True,text=True,check=True,timeout=30).stdout
        cache[start]=asm
        (out/(hex(start)+'.asm')).write_text(asm,encoding='utf-8')
    site=base+int(item['site_rva'],16);target=base+int(item['target_rva'],16)
    line=next((s for s in cache[start].splitlines() if re.match(r'\s*'+format(site,'x')+r':',s)),None)
    if line and re.search(r'\b0x'+format(target,'x')+r'\b',line):
        item['instruction_verified']=True
        item['instruction']=line.strip()
report={'client_sha256':EXPECTED_SHA256,'on_disk_only':True,'targets':list(targets.values()),'references':candidates,
        'warning':'A decoded reference establishes a code relationship, not message semantics or a callable ABI.'}
report['static_pointers']=[]
for target in args.rva:
    needle=struct.pack('<Q',base+target)
    for section in pe.sections:
        if section.characteristics&0x20000000:continue
        raw=data[section.pointerto_raw_data:section.pointerto_raw_data+section.sizeof_raw_data];cursor=0
        while True:
            offset=raw.find(needle,cursor)
            if offset<0:break
            cursor=offset+1
            if (section.virtual_address+offset)%8:continue
            report['static_pointers'].append({'site_rva':hex(section.virtual_address+offset),'target_rva':hex(target)})
(out/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
(out/('report-'+hashlib.sha256(json.dumps(report,sort_keys=True).encode()).hexdigest()[:16]+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,ensure_ascii=False))
