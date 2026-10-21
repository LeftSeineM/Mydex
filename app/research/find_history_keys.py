"""Find authenticated database raw-key literals in this user's known client.
Read-only process access. Persist only keys matching active message/contact DBs,
encrypted with Windows CurrentUser DPAPI. Never print raw bytes or addresses.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import time
from Crypto.Cipher import AES
from external_reader import Reader
from history_crypto import verify_page,dpapi
from run_native_observer import CLIENT,EXPECTED_SHA256,ROOT
PATTERN=re.compile(rb"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{96})(?![0-9A-Fa-f])")
CODEC_PATTERN=re.compile(re.escape(struct.pack('<5i',16,32,16,16,4096)))
def codec_candidate(process,address,salt_pages,diagnostics=None):
    """Candidate SQLCipher codec_ctx layout from upstream v4.6.1 sqlcipher.c.
    A structural match is only a candidate; page HMAC remains mandatory.
    """
    try:
        header=process.read(address,256)
        if struct.unpack_from('<5i',header,12)!=(16,32,16,16,4096):return None
        if diagnostics is not None:
            numeric=[x if -1<=x<=1048576 else None for x in struct.unpack_from('<15i',header)]
            if numeric not in diagnostics['parameter_shapes'] and len(diagnostics['parameter_shapes'])<8:
                diagnostics['parameter_shapes'].append(numeric)
        pointers=[struct.unpack_from('<Q',header,n)[0] for n in range(48,256,8)]
        pointers=[p for p in pointers if 65536<=p<0x7fffffffffff]
        salts=[]
        for pointer in pointers:
            try:
                salt=process.read(pointer,16)
                if salt in salt_pages:salts.append(salt)
            except OSError:continue
        if not salts:return None
        if diagnostics is not None:diagnostics['contexts_with_matching_salt']+=1
        if diagnostics is not None:
            provider=struct.unpack_from('<Q',header,0x78)[0]
            try:
                table=process.read(provider,256)
                module_base=diagnostics['_module_base'];module_size=diagnostics['_module_size']
                slots=[hex(p-module_base) if module_base<=p<module_base+module_size else None
                       for p in struct.unpack('<32Q',table)]
                if slots not in diagnostics['provider_tables'] and len(diagnostics['provider_tables'])<4:
                    diagnostics['provider_tables'].append(slots)
            except OSError:pass
        candidates=set()
        for pointer in pointers:
            try:
                context=process.read(pointer,96)
                for offset in range(0,65,8):
                    candidates.add(context[offset:offset+32])
                    key_ptr=struct.unpack_from('<Q',context,offset)[0]
                    if 65536<=key_ptr<0x7fffffffffff:
                        try:candidates.add(process.read(key_ptr,32))
                        except OSError:continue
            except OSError:continue
        for key in candidates:
            if diagnostics is not None:diagnostics['binary_keys_checked']+=1
            for salt in salts:
                if verify_page(salt_pages[salt],1,key,salt):return salt,key
                header_plain=AES.new(key,AES.MODE_CBC,salt_pages[salt][-80:-64]).decrypt(salt_pages[salt][16:112])
                if header_plain[:2]==b'\x10\x00' and header_plain[2] in (1,2) and header_plain[3] in (1,2) and header_plain[4:8]==b'\x50\x40\x20\x20':
                    if diagnostics is not None:diagnostics['sqlite_header_candidates']+=1
        return None
    except OSError:return None
def scan(pid, data_dir=None):
    data_dir=Path(data_dir) if data_dir is not None else ROOT/'.local'
    profile=json.loads((data_dir/'history-file-profile.json').read_text())
    files=[];salt_pages={}
    for row in profile:
        path=Path(row['parent'])/row['name']
        if row['name'] not in ('contact.db','session.db','message_0.db','message_1.db','message_2.db','message_3.db'):continue
        with path.open('rb') as stream:page=stream.read(4096)
        if len(page)!=4096 or page[:16]==b'SQLite format 3\0':continue
        files.append((str(path),page[:16].hex()));salt_pages[page[:16]]=page
    if not files:raise ValueError('No active encrypted history files')
    if hashlib.sha256(CLIENT.read_bytes()).hexdigest()!=EXPECTED_SHA256:raise ValueError('Unsupported client build')
    found={};seen=set();read_bytes=0;read_errors=0;started=time.monotonic();literal_candidates=0;codec_candidates=0
    protected_path=data_dir/'history-keys.dpapi'
    if protected_path.exists():
        saved=json.loads(dpapi(protected_path.read_bytes(),True))
        for item in saved.get('files',[]):
            salt=bytes.fromhex(item['salt']);key=bytes.fromhex(item['key'])
            if salt in salt_pages and verify_page(salt_pages[salt],1,key,salt):
                found[salt.hex()]=key.hex()
    diagnostics={'parameter_shapes':[],'contexts_with_matching_salt':0,'binary_keys_checked':0,
                 'sqlite_header_candidates':0,'provider_tables':[]}
    with Reader(pid) as process:
        if process.image_path().resolve()!=(CLIENT.parent.parent/'Weixin.exe').resolve():raise ValueError('Unexpected target')
        diagnostics['_module_base'],diagnostics['_module_size']=process.module(CLIENT)
        for base,size in process.regions():
            tail=b''
            for offset in range(0,size,1048576):
                try:data=process.read(base+offset,min(1048576,size-offset))
                except OSError:read_errors+=1;tail=b'';continue
                read_bytes+=len(data);joined=tail+data
                for match in CODEC_PATTERN.finditer(joined):
                    address=base+offset-len(tail)+match.start()-12
                    codec_candidates+=1
                    candidate=codec_candidate(process,address,salt_pages,diagnostics)
                    if candidate:found[candidate[0].hex()]=candidate[1].hex()
                for match in PATTERN.finditer(joined):
                    raw=bytes.fromhex(match.group(1).decode('ascii'))
                    if raw in seen:continue
                    seen.add(raw)
                    literal_candidates+=1
                    possible=[raw[32:]] if len(raw)==48 else list(salt_pages)
                    for salt in possible:
                        if salt in salt_pages and salt.hex() not in found and verify_page(salt_pages[salt],1,raw[:32],salt):
                            found[salt.hex()]=raw[:32].hex()
                    if len(seen)>10000:raise ValueError('Candidate limit reached')
                tail=joined[-110:]
                if len(found)==len(salt_pages):break
            if len(found)==len(salt_pages):break
            if read_bytes>2147483648 or time.monotonic()-started>60:break
    matches=[{'path':path,'salt':salt,'key':found[salt]} for path,salt in files if salt in found]
    if matches:
        protected=dpapi(json.dumps({'pid':pid,'files':matches}).encode('utf-8'))
        (data_dir/'history-keys.dpapi').write_bytes(protected)
    diagnostics={k:v for k,v in diagnostics.items() if not k.startswith('_')}
    report={'pid':pid,'read_bytes':read_bytes,'read_errors':read_errors,'active_databases':len(files),
            'authenticated_databases':len(matches),'elapsed_seconds':round(time.monotonic()-started,2),
            'literal_candidates':literal_candidates,
            'codec_candidates':codec_candidates,
            'codec_diagnostics':diagnostics,
            'plaintext_keys_persisted':False,'group_history_read':False}
    (data_dir/'history-key-status.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--data-dir',type=Path)
    args=parser.parse_args()
    print(json.dumps(scan(args.pid,args.data_dir)))
