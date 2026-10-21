"""Read-only SQLCipher-4 page primitives; no whole-database plaintext export.
Raw keys must authenticate a real page before they are accepted or persisted.
"""
import hashlib
import hmac
import ctypes as C
from ctypes import wintypes as W
from Crypto.Cipher import AES
PAGE_SIZE=4096
RESERVE=80
def hmac_key(key,salt):
    return hashlib.pbkdf2_hmac('sha512',key,bytes(x^0x3a for x in salt),2,32)
def verify_page(page,number,key,salt):
    if len(page)!=PAGE_SIZE or len(key)!=32 or len(salt)!=16 or not 1<=number<2**32:return False
    start=16 if number==1 else 0
    expected=hmac.new(hmac_key(key,salt),page[start:-64]+number.to_bytes(4,'little'),'sha512').digest()
    return hmac.compare_digest(expected,page[-64:])
def decrypt_page(page,number,key,salt):
    if not verify_page(page,number,key,salt):raise ValueError('Page authentication failed')
    start=16 if number==1 else 0
    plain=AES.new(key,AES.MODE_CBC,page[-RESERVE:-64]).decrypt(page[start:-RESERVE])
    return (b'SQLite format 3\0' if start else b'')+plain+b'\0'*RESERVE
class Blob(C.Structure):
    _fields_=[('size',W.DWORD),('data',C.POINTER(C.c_ubyte))]
def dpapi(data,unprotect=False):
    library=C.WinDLL('crypt32',use_last_error=True);kernel=C.WinDLL('kernel32')
    function=library.CryptUnprotectData if unprotect else library.CryptProtectData
    function.argtypes=[C.POINTER(Blob),C.c_void_p,C.POINTER(Blob),C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(Blob)]
    function.restype=W.BOOL;kernel.LocalFree.argtypes=[C.c_void_p];kernel.LocalFree.restype=C.c_void_p
    buffer=(C.c_ubyte*len(data)).from_buffer_copy(data);source=Blob(len(data),buffer);output=Blob()
    if not function(C.byref(source),None,None,None,None,1,C.byref(output)):raise C.WinError(C.get_last_error())
    try:return C.string_at(output.data,output.size)
    finally:kernel.LocalFree(output.data)
