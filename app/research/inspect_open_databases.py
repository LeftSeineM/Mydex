"""Read target process's open disk-file paths, never file contents or keys.

Duplicate query handles only. Skip pipe/device handles before requesting a name.
This locates the active data directory without relying on obsolete default paths.
"""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import os
from external_reader import Reader
ROOT=Path(__file__).resolve().parents[1]
class HandleEntry(C.Structure):
    _fields_=[('object',C.c_void_p),('pid',C.c_size_t),('handle',C.c_size_t),
              ('access',W.DWORD),('trace',W.WORD),('type_index',W.WORD),
              ('attributes',W.DWORD),('reserved',W.DWORD)]
def inventory(pid):
    k=C.WinDLL('kernel32',use_last_error=True);nt=C.WinDLL('ntdll')
    specs={'OpenProcess':([W.DWORD,W.BOOL,W.DWORD],W.HANDLE),
           'GetCurrentProcess':([],W.HANDLE),'CloseHandle':([W.HANDLE],W.BOOL),
           'DuplicateHandle':([W.HANDLE,W.HANDLE,W.HANDLE,C.POINTER(W.HANDLE),W.DWORD,W.BOOL,W.DWORD],W.BOOL),
           'GetFileType':([W.HANDLE],W.DWORD),
           'GetFinalPathNameByHandleW':([W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD],W.DWORD)}
    for name,(args,result) in specs.items():fn=getattr(k,name);fn.argtypes=args;fn.restype=result
    nt.NtQuerySystemInformation.argtypes=[W.ULONG,C.c_void_p,W.ULONG,C.POINTER(W.ULONG)]
    nt.NtQuerySystemInformation.restype=W.LONG
    size=1048576
    while True:
        data=C.create_string_buffer(size);needed=W.ULONG()
        status=nt.NtQuerySystemInformation(64,data,size,C.byref(needed))
        if status==0:break
        if status!=-1073741820:raise OSError('Handle inventory status '+hex(status&0xffffffff))
        size=max(size*2,needed.value+65536)
        if size>67108864:raise ValueError('Handle inventory exceeded bound')
    count=int.from_bytes(data.raw[:8],'little')
    if count>(size-16)//C.sizeof(HandleEntry):raise ValueError('Invalid handle inventory')
    target=k.OpenProcess(0x40,False,pid)
    if not target:raise C.WinError(C.get_last_error())
    paths=set();duplicated=0;disk_handles=0
    try:
        current=k.GetCurrentProcess()
        for index in range(count):
            entry=HandleEntry.from_buffer_copy(data,16+index*C.sizeof(HandleEntry))
            if entry.pid!=pid:continue
            duplicate=W.HANDLE()
            if not k.DuplicateHandle(target,entry.handle,current,C.byref(duplicate),0,False,2):continue
            duplicated+=1
            try:
                if k.GetFileType(duplicate)!=1:continue
                disk_handles+=1;buffer=C.create_unicode_buffer(32768)
                length=k.GetFinalPathNameByHandleW(duplicate,buffer,len(buffer),0)
                if not 0<length<len(buffer):continue
                path=buffer.value
                if path.startswith('\\\\?\\'):path=path[4:]
                if Path(path).suffix.lower() in ('.db','.sqlite','.sqlite3') or path.lower().endswith(('.db-wal','.db-shm')):
                    paths.add(path)
            finally:k.CloseHandle(duplicate)
    finally:k.CloseHandle(target)
    return {'pid':pid,'duplicated_query_handles':duplicated,'disk_handles':disk_handles,
            'database_paths':sorted(paths),'contents_read':False,'keys_read':False}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--self-test',action='store_true');args=parser.parse_args()
    if args.self_test:
        path=ROOT/'.local/handle-fixture.db'
        with path.open('wb') as file:
            file.write(b'fixture');file.flush()
            report=inventory(os.getpid())
            if str(path) not in report['database_paths']:raise AssertionError('Open file not found')
        path.unlink();print(json.dumps({'passed':True,'handles':report['duplicated_query_handles']}));return
    with Reader(args.pid) as process:
        if process.image_path().resolve()!=Path(configured_path('client_exe', '')).resolve():
            raise ValueError('Only the known Weixin client is accepted')
    report=inventory(args.pid)
    (ROOT/'.local/open-databases.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='database_paths'}))
    print(json.dumps({'database_names':[Path(p).name for p in report['database_paths']]}))
if __name__=='__main__':main()
