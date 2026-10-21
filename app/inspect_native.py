"""Read-only PE reconnaissance. Never loads DLLs or opens process/account memory."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct

import lief

KEYWORDS = re.compile(rb"SendText|send_text|SendMessage|MessageSend|SendMsg|RecvMsg|ReceiveMsg|OnAddMsg|AddMsg|NewSync|MsgService|MessageService|ChatService|ChatRoom|MessagePipe|NamedPipe|MMMojo|LocalIPC", re.I)
IMPORTS = re.compile(r"pipe|send|recv|connect|socket|mmmojo|ilink|LoadLibrary|GetProcAddress", re.I)


def inspect(path):
    pe = lief.PE.parse(str(path))
    if pe is None:
        raise ValueError('Not a PE file: ' + str(path))
    sections = list(pe.sections)

    def rva_at(offset):
        for section in sections:
            if section.pointerto_raw_data <= offset < section.pointerto_raw_data + section.sizeof_raw_data:
                return section.virtual_address + offset - section.pointerto_raw_data
        return None

    exports = pe.get_export() if pe.has_exports else None
    report = {
        'path': str(path), 'bytes': path.stat().st_size,
        'machine': str(pe.header.machine), 'imagebase': hex(pe.optional_header.imagebase),
        'sections': [{'name': s.name, 'rva': hex(s.virtual_address), 'raw_bytes': s.sizeof_raw_data,
                      'virtual_bytes': s.virtual_size, 'characteristics': hex(s.characteristics)} for s in sections],
        'exports': [{'name': e.name, 'rva': hex(e.address)} for e in exports.entries] if exports else [],
        'imports': [{'dll': imp.name, 'functions': [e.name for e in imp.entries if e.name and IMPORTS.search(e.name)]}
                    for imp in pe.imports],
        'delay_imports': [{'dll': imp.name, 'functions': [e.name for e in imp.entries if e.name and IMPORTS.search(e.name)]}
                         for imp in pe.delay_imports],
        'strings': [],
    }
    with path.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        report['sha256'] = hashlib.sha256(data).hexdigest()
        seen = set()
        for match in KEYWORDS.finditer(data):
            start = data.rfind(b'\0', max(0, match.start() - 300), match.start()) + 1
            end = data.find(b'\0', match.end(), min(len(data), match.end() + 300))
            if not start or end < 0 or end-start > 512 or start in seen:
                continue
            raw = data[start:end]
            if not all(32 <= c <= 126 or c in (9,10,13) for c in raw):
                continue
            seen.add(start)
            rva = rva_at(start)
            if rva is None:
                continue
            report['strings'].append({'rva': hex(rva), 'text': raw.decode('ascii'), 'rip_references': []})
        # Candidate x64 LEA/MOV RIP references; instruction boundaries are NOT yet validated.
        targets = {int(s['rva'], 16): s for s in report['strings']}
        pdata = next((s for s in sections if s.name == '.pdata'), None)
        functions = []
        if pdata:
            raw = data[pdata.pointerto_raw_data:pdata.pointerto_raw_data+pdata.sizeof_raw_data]
            functions = [struct.unpack_from('<III', raw, n)[:2] for n in range(0,len(raw)-11,12)]
            functions = sorted((start,end) for start,end in functions if start and end > start)
        from bisect import bisect_right
        function_starts = [f[0] for f in functions]
        for section in sections:
            if not section.characteristics & 0x20000000:
                continue
            raw = data[section.pointerto_raw_data:section.pointerto_raw_data+section.sizeof_raw_data]
            for match in re.finditer(rb'[\x48\x4c][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', raw):
                offset = match.start()
                if offset+7 > len(raw): continue
                source = section.virtual_address+offset
                target = source+7+struct.unpack_from('<i',raw,offset+3)[0]
                if target not in targets: continue
                slot = bisect_right(function_starts, source)-1
                function = functions[slot] if slot >= 0 and source < functions[slot][1] else None
                refs = targets[target]['rip_references']
                if len(refs)<30:
                    refs.append({'instruction_rva': hex(source), 'candidate_function_rva': hex(function[0]) if function else None})
        report['runtime_function_count'] = len(functions)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = args.client_dir.resolve(strict=True)
    names = ('Weixin.dll', 'mmmojo_64.dll', 'wxpublic.dll', 'ilink_wrapper.dll')
    files = []
    for name in names:
        path = (root/name).resolve(strict=True)
        if path.parent != root: raise ValueError('Unexpected binary path')
        result = inspect(path)
        files.append(result)
        print(json.dumps({'file': name, 'sha256': result['sha256'], 'exports': len(result['exports']),
                          'strings':len(result['strings']), 'runtime_functions':result['runtime_function_count']}, ensure_ascii=False), flush=True)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps({'mode':'static_read_only', 'dlls_executed':False, 'process_memory_read':False,
        'references_are_candidates':True, 'files':files}, ensure_ascii=False,indent=2),encoding='utf-8')


if __name__ == '__main__':
    main()
