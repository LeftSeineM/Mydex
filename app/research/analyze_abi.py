"""Produce version-pinned, static function evidence; never opens a process."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
from bisect import bisect_right
import argparse
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

ROOTS={
    0x766780:'base_message_constructor',
    0x766680:'text_message_constructor_candidate',
    0x6f4c70:'text_message_shared_object_factory_candidate',
    0x6f4d90:'message_manager_getter_candidate',
    0x54b02f0:'text_send_wrapper_candidate',
    0x17f3750:'observed_send_stage_a',
    0x17f7a00:'observed_send_stage_b',
    0x179cb90:'send_stage_result_extraction_candidate',
    0x179ce50:'unobserved_batch_save_candidate',
    0x39edfd0:'newsendmsg_constructor_candidate',
    0x39f28c0:'newsendmsg_request_metadata_candidate',
    0x2e2fbb0:'newsync_operation_candidate',
    0x2e324a0:'observed_sync_request_metadata',
    0x2dbd700:'logout_callback_registration',
    0x2fb010:'task_submission_candidate',
    0x178f040:'message_manager_send_candidate',
    0x178f100:'message_manager_send_core',
    0x3981a30:'send_task_constructor_candidate',
    0x1793050:'send_task_preparation_candidate',
    0x1793c90:'send_task_dispatch_candidate',
    0x2e7c6e0:'sync_field2_constructor',
    0x2e7d0e0:'sync_field2_parser',
    0x679080:'sync_field4_constructor',
}
VTABLES={0x9805968:'text_send_continuation',0x9805878:'logout_callback',
         0x8e534f8:'text_shared_control',0x8e53588:'text_message',
         0x8fc0d48:'newsync_response_proto',0x93d3cf8:'sync_field2_proto',
         0x8e3d058:'sync_field4_proto',0x93d3c78:'sync_command_item_proto'}
# Reviewed leaf bodies have no unwind record; explicit ends include the RET.
LEAF_ENDS={0x2e7c6e0:0x2e7c70b,0x679080:0x6790a8}
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--function',action='append',default=[],metavar='RVA:LABEL')
parser.add_argument('--vtable',action='append',default=[],metavar='RVA:LABEL')
args=parser.parse_args()
for spec in args.vtable:
    address,label=spec.split(':',1)
    if not re.fullmatch(r'[a-z0-9_]+',label):raise ValueError('Invalid label')
    VTABLES[int(address,0)]=label
for spec in args.function:
    address,label=spec.split(':',1)
    if not re.fullmatch(r'[a-z0-9_]+',label):raise ValueError('Invalid label')
    ROOTS[int(address,0)]=label
data=CLIENT.read_bytes()
if hashlib.sha256(data).hexdigest()!=EXPECTED_SHA256:raise ValueError('Client build changed')
pe=lief.PE.parse(str(CLIENT));base=pe.optional_header.imagebase
pdata=next(s for s in pe.sections if s.name=='.pdata')
raw=data[pdata.pointerto_raw_data:pdata.pointerto_raw_data+pdata.sizeof_raw_data]
funcs=sorted((a,b) for a,b,_ in struct.iter_unpack('<III',raw[:len(raw)//12*12]) if a and b>a)
starts=[a for a,b in funcs]
out=ROOT/'.local/abi';out.mkdir(exist_ok=True)

def rva_bytes(rva,size):
    section=next((s for s in pe.sections if s.virtual_address<=rva and rva+size<=s.virtual_address+s.sizeof_raw_data),None)
    if section is None:raise ValueError('RVA outside mapped file bytes: '+hex(rva))
    offset=section.pointerto_raw_data+rva-section.virtual_address
    return data[offset:offset+size]

vtables=[]
for rva,label in VTABLES.items():
    record={'rva':hex(rva),'label':label,'slots':[]}
    try:
        col=struct.unpack('<Q',rva_bytes(rva-8,8))[0]-base
        signature,offset,cd_offset,type_rva,hierarchy_rva,self_rva=struct.unpack('<6I',rva_bytes(col,24))
        if signature==1 and self_rva==col:
            name_bytes=rva_bytes(type_rva+16,512).split(b'\0',1)[0]
            name=name_bytes.decode('ascii') if all(32<=c<127 for c in name_bytes) else None
            record['rtti']={'type_name':name,'name_readable':name is not None,'type_descriptor_rva':hex(type_rva),'complete_object_locator_rva':hex(col),'object_offset':offset,'hierarchy_rva':hex(hierarchy_rva)}
    except (ValueError,struct.error):pass
    for slot in range(12):
        target=struct.unpack('<Q',rva_bytes(rva+slot*8,8))[0]-base
        index=bisect_right(starts,target)-1
        executable=any(s.characteristics&0x20000000 and s.virtual_address<=target<s.virtual_address+s.sizeof_raw_data for s in pe.sections)
        if not executable:break
        unwind_entry=index>=0 and funcs[index][0]==target
        record['slots'].append({'index':slot,'function_rva':hex(target),'unwind_entry':unwind_entry,'boundary':'candidate; adjacent tables may follow'})
        if unwind_entry:ROOTS.setdefault(target,label+'_slot_'+str(slot))
    vtables.append(record)
records=[]
for start,label in ROOTS.items():
    index=bisect_right(starts,start)-1
    if start in LEAF_ENDS:
        end=LEAF_ENDS[start];boundary_source='manually_reviewed_leaf_ret'
    else:
        if index<0 or funcs[index][0]!=start:raise ValueError('Not an unwind function entry: '+hex(start))
        end=funcs[index][1];boundary_source='pe_unwind_table'
    section=next(s for s in pe.sections if s.virtual_address<=start<s.virtual_address+s.sizeof_raw_data)
    offset=section.pointerto_raw_data+start-section.virtual_address
    code=data[offset:offset+end-start]
    disasm=subprocess.run([configured_path('objdump', ''),'-d','-M','intel',
        '--start-address='+hex(base+start),'--stop-address='+hex(base+end),str(CLIENT)],
        capture_output=True,text=True,check=True,timeout=30).stdout
    (out/(label+'.asm')).write_text(disasm,encoding='utf-8')
    calls=[]
    for line in disasm.splitlines():
        match=re.search(r'^\s*([0-9a-f]+):.*\bcall\s+0x([0-9a-f]+)',line)
        if match:
            target=int(match.group(2),16)-base
            calls.append({'site_rva':hex(int(match.group(1),16)-base),'target_rva':hex(target)})
    records.append({'label':label,'rva':hex(start),'end_rva':hex(end),'size':len(code),
        'boundary_source':boundary_source,
        'entry_bytes':code[:24].hex(),'code_sha256':hashlib.sha256(code).hexdigest(),
        'call_targets':calls,'abi_verified':False,'sending_enabled':False})
report={'client_sha256':EXPECTED_SHA256,'client_version':'4.1.15.13','mode':'on_disk_static_only',
    'functions':records,'vtables':vtables,'warning':'Labels express hypotheses; these addresses are not callable API definitions.'}
(out/'profile.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'functions':len(records),'profile':str(out/'profile.json'),'client_not_executed':True}))
for record in records[:2]:print(json.dumps(record))
