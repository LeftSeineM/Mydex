"""Read-only Windows process inspection. No injection, debugging or memory writes."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path

class Region(C.Structure):
    _fields_=[('base',C.c_uint64),('allocation_base',C.c_uint64),('allocation_protect',W.DWORD),
              ('alignment',W.DWORD),('size',C.c_uint64),('state',W.DWORD),('protect',W.DWORD),
              ('type',W.DWORD),('alignment2',W.DWORD)]

class ModuleInfo(C.Structure):
    _fields_=[('base',C.c_void_p),('size',W.DWORD),('entry',C.c_void_p)]

class Reader:
    ACCESS=0x400|0x10  # QUERY_INFORMATION | VM_READ only
    def __init__(self,pid):
        if C.sizeof(C.c_void_p)!=8:raise RuntimeError('64-bit reader required')
        self.k=C.WinDLL('kernel32',use_last_error=True)
        signatures={
            'OpenProcess':([W.DWORD,W.BOOL,W.DWORD],W.HANDLE),
            'CloseHandle':([W.HANDLE],W.BOOL),
            'ReadProcessMemory':([W.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],W.BOOL),
            'VirtualQueryEx':([W.HANDLE,C.c_void_p,C.POINTER(Region),C.c_size_t],C.c_size_t),
            'QueryFullProcessImageNameW':([W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)],W.BOOL),
            'K32EnumProcessModulesEx':([W.HANDLE,C.POINTER(C.c_void_p),W.DWORD,C.POINTER(W.DWORD),W.DWORD],W.BOOL),
            'K32GetModuleFileNameExW':([W.HANDLE,C.c_void_p,W.LPWSTR,W.DWORD],W.DWORD),
            'K32GetModuleInformation':([W.HANDLE,C.c_void_p,C.POINTER(ModuleInfo),W.DWORD],W.BOOL),
        }
        for name,(args,result) in signatures.items():
            fn=getattr(self.k,name);fn.argtypes=args;fn.restype=result
        self.handle=self.k.OpenProcess(self.ACCESS,False,pid)
        if not self.handle:raise C.WinError(C.get_last_error())
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def close(self):
        if self.handle:self.k.CloseHandle(self.handle);self.handle=None
    def image_path(self):
        buf=C.create_unicode_buffer(32768);size=W.DWORD(len(buf))
        if not self.k.QueryFullProcessImageNameW(self.handle,0,buf,C.byref(size)):raise C.WinError(C.get_last_error())
        return Path(buf.value)
    def module(self,path):
        modules=(C.c_void_p*4096)();needed=W.DWORD()
        if not self.k.K32EnumProcessModulesEx(self.handle,modules,C.sizeof(modules),C.byref(needed),3):raise C.WinError(C.get_last_error())
        if needed.value>C.sizeof(modules):raise ValueError('Module inventory truncated')
        for mod in modules[:needed.value//C.sizeof(C.c_void_p)]:
            buf=C.create_unicode_buffer(32768)
            if not self.k.K32GetModuleFileNameExW(self.handle,mod,buf,len(buf)):continue
            if Path(buf.value).resolve()!=Path(path).resolve():continue
            info=ModuleInfo()
            if not self.k.K32GetModuleInformation(self.handle,mod,C.byref(info),C.sizeof(info)):raise C.WinError(C.get_last_error())
            return info.base,info.size
        raise ValueError('Expected module is not loaded')
    def read(self,address,size):
        if not 0<size<=1048576:raise ValueError('Read size out of bounds')
        buf=C.create_string_buffer(size);copied=C.c_size_t()
        if not self.k.ReadProcessMemory(self.handle,address,buf,size,C.byref(copied)) or copied.value!=size:
            raise OSError('Requested range is no longer readable')
        return buf.raw
    def regions(self):
        address=0
        while address<0x7fffffffffff:
            info=Region()
            if self.k.VirtualQueryEx(self.handle,address,C.byref(info),C.sizeof(info))!=C.sizeof(info):break
            if info.size==0 or info.base+info.size<=address:raise ValueError('Invalid region boundary')
            address=info.base+info.size
            if info.state==0x1000 and info.type==0x20000 and info.protect in (0x04,0x08):yield info.base,info.size
