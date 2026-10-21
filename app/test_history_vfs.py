import ctypes
import hashlib,hmac
from pathlib import Path
import sqlite3,struct,sys,tempfile,unittest
import apsw
from Crypto.Cipher import AES
sys.path.insert(0,str(Path(__file__).resolve().parent/'research'))
from history_vfs import HistoryView,SnapshotChanged,wal_overlay
from history_crypto import hmac_key
class HistoryVFSTests(unittest.TestCase):
    def test_send_cursor_ignores_body_and_rejects_other_scope(self):
        from history_reader import TargetHistory
        from lab import UserError
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'message_0.db'
            writer=sqlite3.connect(path)
            writer.execute('CREATE TABLE Msg_fixture(local_id INTEGER PRIMARY KEY, body TEXT)')
            writer.executemany('INSERT INTO Msg_fixture VALUES(?,?)', [(1,'a'),(900,'b')])
            writer.commit();writer.close()
            reader=TargetHistory.__new__(TargetHistory)
            reader.aliases={'target'};reader.table='Msg_fixture';reader.keys={str(path):(None,None)}
            self.assertEqual(reader.latest_cursor(str(path),'target'),900)
            with self.assertRaises(UserError):reader.latest_cursor(str(path),'another group')
            with self.assertRaises(UserError):reader.latest_cursor(str(Path(folder)/'other.db'),'target')
            reader.table='Msg_absent'
            self.assertEqual(reader.latest_cursor(str(path),'target'),0)

    def test_live_wal_overlay_readonly_and_change_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.db';writer=sqlite3.connect(path)
            writer.execute('PRAGMA journal_mode=WAL');writer.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,text TEXT)')
            writer.execute('INSERT INTO events VALUES(1,?)',('讨论群助手',));writer.commit()
            before=hashlib.sha256(path.read_bytes()).hexdigest()
            try:
                with HistoryView(path) as view:
                    self.assertEqual(view.query('SELECT text FROM events'),[('讨论群助手',)])
                    with self.assertRaises(apsw.ReadOnlyError):view.query("INSERT INTO events VALUES(2,'bad')")
                    writer.execute('INSERT INTO events VALUES(3,?)',('新事务',));writer.commit()
                    with self.assertRaises(SnapshotChanged):view.query('SELECT * FROM events')
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)
            finally:writer.close()
    def test_encrypted_page_view_uses_real_sqlite_engine(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'plain.db';encrypted=Path(folder)/'encrypted.db'
            writer=apsw.Connection(str(path));reserve=ctypes.c_int(80)
            self.assertTrue(writer.file_control('main',apsw.SQLITE_FCNTL_RESERVE_BYTES,ctypes.addressof(reserve)))
            writer.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,text TEXT)')
            writer.executemany('INSERT INTO events VALUES(?,?)',[(i,'中文记录 '+str(i)+' 内容'*1200) for i in range(12)])
            expected=list(writer.execute('SELECT * FROM events ORDER BY id'));writer.close()
            plain=path.read_bytes();self.assertEqual(plain[20],80)
            key=b'K'*32;salt=b'S'*16;out=bytearray()
            for offset in range(0,len(plain),4096):
                number=offset//4096+1;start=16 if number==1 else 0;iv=number.to_bytes(16,'little')
                body=AES.new(key,AES.MODE_CBC,iv).encrypt(plain[offset+start:offset+4096-80])
                mac=hmac.new(hmac_key(key,salt),body+iv+number.to_bytes(4,'little'),'sha512').digest()
                out.extend((salt if number==1 else b'')+body+iv+mac)
            encrypted.write_bytes(out);before=hashlib.sha256(out).hexdigest()
            with HistoryView(encrypted,key,salt) as view:
                self.assertEqual(view.query('SELECT * FROM events ORDER BY id'),expected)
                self.assertGreater(view.snapshot.pages_read,2)
            self.assertEqual(hashlib.sha256(encrypted.read_bytes()).hexdigest(),before)
            damaged=bytearray(out);damaged[222]^=1;encrypted.write_bytes(damaged)
            with self.assertRaises(ValueError):HistoryView(encrypted,key,salt)
if __name__=='__main__':unittest.main()
