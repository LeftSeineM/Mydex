"""Read-only, page-authenticated SQLite view. Decrypted pages remain in RAM.

Committed WAL frames are overlaid in RAM. Changes to source metadata invalidate
the view instead of silently mixing transactions. Never writes original DB/WAL.
"""
from collections import OrderedDict
import os
from pathlib import Path
import struct
import uuid
import apsw
from history_crypto import decrypt_page

class SnapshotChanged(ValueError):pass
def identity(path):
    try:
        s=Path(path).stat();return (s.st_size,s.st_mtime_ns,s.st_ino)
    except FileNotFoundError:return None
def checksum(data,endian,state=(0,0)):
    if len(data)%8:raise ValueError('Invalid WAL checksum input')
    a,b=state
    for x,y in struct.iter_unpack(endian+'II',data):
        a=(a+x+b)&0xffffffff;b=(b+y+a)&0xffffffff
    return a,b
def wal_overlay(path,page_size):
    if not Path(path).exists():return {},None
    if Path(path).stat().st_size>134217728:raise ValueError('WAL snapshot exceeds 128 MiB bound')
    committed={};pending={};database_size=None
    with Path(path).open('rb') as stream:
        header=stream.read(32)
        if not header:return {},None
        if len(header)!=32:raise SnapshotChanged('WAL header incomplete')
        magic,version,size=struct.unpack_from('>III',header)
        if magic not in (0x377f0682,0x377f0683) or version!=3007000 or size!=page_size:
            raise ValueError('Unsupported WAL header')
        endian='<' if magic==0x377f0682 else '>'
        state=checksum(header[:24],endian)
        if state!=struct.unpack_from('>II',header,24):raise ValueError('WAL header checksum mismatch')
        while True:
            frame=stream.read(24)
            if not frame:break
            if len(frame)!=24:break
            payload=stream.read(page_size)
            if len(payload)!=page_size or frame[8:16]!=header[16:24]:break
            number,commit_size=struct.unpack_from('>II',frame)
            if not number:break
            current=checksum(payload,endian,checksum(frame[:8],endian,state))
            if current!=struct.unpack_from('>II',frame,16):break
            state=current;pending[number]=payload
            if commit_size:
                committed.update(pending);pending.clear();database_size=commit_size
        if database_size is not None:committed={n:p for n,p in committed.items() if n<=database_size}
    return committed,database_size

class PageSnapshot:
    def __init__(self,path,key=None,salt=None):
        self.path=Path(path).resolve(strict=True);self.wal=Path(str(self.path)+'-wal')
        self.key,self.salt=key,salt;self.before=(identity(self.path),identity(self.wal))
        self.stream=self.path.open('rb');self.cache=OrderedDict();self.pages_read=0
        try:
            if key is None:
                header=self.stream.read(100)
                if header[:16]!=b'SQLite format 3\0':raise ValueError('Not a plaintext fixture')
                self.page_size=int.from_bytes(header[16:18],'big');self.page_size=65536 if self.page_size==1 else self.page_size
            else:
                self.page_size=4096
                self.stream.seek(0);page=self.stream.read(self.page_size)
                header=decrypt_page(page,1,key,salt)[:100]
                if header[16:18]!=b'\x10\x00' or header[20]!=80:raise ValueError('Unexpected SQLCipher page layout')
            self.overlay,self.commit_pages=wal_overlay(self.wal,self.page_size)
            self.size=self.commit_pages*self.page_size if self.commit_pages is not None else self.before[0][0]
            self.check()
        except Exception:self.stream.close();raise
    def check(self):
        if (identity(self.path),identity(self.wal))!=self.before:raise SnapshotChanged('Database changed during read; retry required')
    def page(self,number):
        if not 1<=number<=self.size//self.page_size:raise ValueError('Page number out of bounds')
        if number in self.cache:
            self.cache.move_to_end(number);return self.cache[number]
        raw=self.overlay.get(number)
        if raw is None:
            self.stream.seek((number-1)*self.page_size);raw=self.stream.read(self.page_size)
        if len(raw)!=self.page_size:raise SnapshotChanged('Page truncated')
        plain=decrypt_page(raw,number,self.key,self.salt) if self.key is not None else raw
        if number==1:
            # WAL has already been applied to this immutable view in RAM.
            data=bytearray(plain);data[18:20]=b'\x01\x01'
            if self.commit_pages is not None:data[28:32]=self.commit_pages.to_bytes(4,'big')
            plain=bytes(data)
        self.cache[number]=plain;self.pages_read+=1
        if len(self.cache)>256:self.cache.popitem(last=False)
        return plain
    def read(self,amount,offset):
        if amount<0 or amount>1048576 or offset<0:raise ValueError('Read outside bound')
        result=bytearray()
        while len(result)<amount and offset<self.size:
            number,within=divmod(offset,self.page_size);page=self.page(number+1)
            count=min(amount-len(result),self.page_size-within,self.size-offset)
            result.extend(page[within:within+count]);offset+=count
        # SQLite treats the remaining bytes as a short read; pad with zeros.
        result.extend(b'\0'*(amount-len(result)));return bytes(result)
    def close(self):self.stream.close();self.cache.clear();self.overlay.clear()

class SnapshotFile(apsw.VFSFile):
    def __init__(self,base,name,flags,snapshot):
        self.snapshot=snapshot;super().__init__(base,name,flags)
    def xRead(self,amount,offset):return self.snapshot.read(amount,offset)
    def xFileSize(self):return self.snapshot.size
    def xWrite(self,*args):raise apsw.ReadOnlyError('History view is read-only')
    def xTruncate(self,*args):raise apsw.ReadOnlyError('History view is read-only')
    def xSync(self,*args):raise apsw.ReadOnlyError('History view is read-only')

class SnapshotVFS(apsw.VFS):
    def __init__(self,snapshot):
        self.snapshot=snapshot;self.name='wx-history-'+uuid.uuid4().hex;self.base=apsw.vfs_names()[0]
        super().__init__(self.name,self.base)
    def xOpen(self,name,flags):
        filename=name.filename() if isinstance(name,apsw.URIFilename) else name
        if filename is None or Path(filename).resolve()!=self.snapshot.path or not flags[0]&apsw.SQLITE_OPEN_READONLY:
            raise apsw.ReadOnlyError('Only the selected original database may be opened')
        return SnapshotFile(self.base,name,flags,self.snapshot)
    def xDelete(self,*args):raise apsw.ReadOnlyError('History view cannot delete files')

class HistoryView:
    def __init__(self,path,key=None,salt=None):
        self.snapshot=PageSnapshot(path,key,salt);self.vfs=SnapshotVFS(self.snapshot)
        try:
            self.db=apsw.Connection(self.snapshot.path.as_uri()+'?immutable=1',
                                    flags=apsw.SQLITE_OPEN_READONLY|apsw.SQLITE_OPEN_URI,vfs=self.vfs.name)
            self.db.execute('PRAGMA mmap_size=0');self.db.execute('PRAGMA query_only=ON')
        except Exception:self.vfs.unregister();self.snapshot.close();raise
    def __enter__(self):return self
    def __exit__(self,*args):self.db.close();self.vfs.unregister();self.snapshot.close()
    def query(self,sql,bindings=()):
        self.snapshot.check();rows=list(self.db.execute(sql,bindings));self.snapshot.check();return rows
