"""Trace selected literal references in an on-disk PE, without executing it."""
import bisect
import json
import mmap
from pathlib import Path
import re
import struct

import lief

ROOT = Path(__file__).resolve().parent
audit = json.loads((ROOT / '.local/native-audit.json').read_text(encoding='utf-8'))
record = audit['files'][0]
path = Path(record['path'])
pe = lief.PE.parse(str(path))
sections = list(pe.sections)
base = pe.optional_header.imagebase
anchors = [s for s in record['strings'] if s['text'] in (
    'message::send_text_message', 'send_text_message_failed: MessageManager is unavailable',
    'send_text_message_failed (logout)', 'Begin StartSendMessageSyncStage', 'SaveSendMessagesAtOnce',
    '/cgi-bin/micromsg-bin/newsendmsg', '/cgi-bin/micromsg-bin/newsync')]


def rva_at(offset):
    return next((s.virtual_address + offset - s.pointerto_raw_data for s in sections
                 if s.pointerto_raw_data <= offset < s.pointerto_raw_data+s.sizeof_raw_data), None)


with path.open('rb') as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
    import hashlib
    if hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError('Binary changed since inventory; rerun inspect_native.py')
    pdata = next(s for s in sections if s.name == '.pdata')
    raw = data[pdata.pointerto_raw_data:pdata.pointerto_raw_data+pdata.sizeof_raw_data]
    functions = sorted((start,end) for start,end,_ in struct.iter_unpack('<III',raw[:len(raw)//12*12]) if start and end>start)
    starts = [f[0] for f in functions]
    targets = {}
    for anchor in anchors:
        rva = int(anchor['rva'],16)
        anchor['pointer_locations'] = []
        anchor['expanded_references'] = []
        # Literal descriptors sometimes point to a small header before the bytes.
        for delta in (0,-8,-16,-24,-32): targets.setdefault(rva+delta,[]).append((anchor,delta,'literal_or_header'))
        pattern = struct.pack('<Q',base+rva)
        cursor=0
        while True:
            offset=data.find(pattern,cursor)
            if offset<0: break
            cursor=offset+1
            location=rva_at(offset)
            if location is not None:
                anchor['pointer_locations'].append(hex(location))
                targets.setdefault(location,[]).append((anchor,0,'literal_pointer'))
    for section in sections:
        if not section.characteristics & 0x20000000: continue
        raw=data[section.pointerto_raw_data:section.pointerto_raw_data+section.sizeof_raw_data]
        pattern=rb'(?:[\x48\x4c][\x8d\x8b\x89]|\x0f[\x10\x28\x6f])[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'
        for match in re.finditer(pattern,raw):
            offset=match.start();end=match.end()
            if end+4>len(raw):continue
            target=section.virtual_address+end+4+struct.unpack_from('<i',raw,end)[0]
            for anchor,delta,kind in targets.get(target,[]):
                source=section.virtual_address+offset
                index=bisect.bisect_right(starts,source)-1
                function=functions[index] if index>=0 and source<functions[index][1] else None
                anchor['expanded_references'].append({'rva':hex(source),'function_rva':hex(function[0]) if function else None,
                    'function_end_rva':hex(function[1]) if function else None,'target_kind':kind,'literal_delta':delta})
out={'sha256':record['sha256'],'static_candidates_only':True,'anchors':anchors}
(ROOT/'.local/native-traces.json').write_text(json.dumps(out,indent=2),encoding='utf-8')
for anchor in anchors:
    print(json.dumps(anchor),flush=True)
