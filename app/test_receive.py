import ctypes
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent/'research'))
from decode_receive import decode_add_message,DecodeError,fields
from run_native_receiver import Config,State,Slot,Command

def integer(n):
    out=bytearray()
    while n>=128:out.append((n&127)|128);n>>=7
    out.append(n);return bytes(out)
def blob(field,data):return integer(field*8+2)+integer(len(data))+data
def number(field,n):return integer(field*8)+integer(n)
def string(field,text):return blob(field,blob(1,text.encode('utf-8')))
def sample(room='123456@chatroom',receiver='wxid_bot',text='WXRECV1006'):
    return number(1,10)+string(2,room)+string(3,receiver)+number(4,1)+string(5,'wxid_M:\n'+text)+number(9,1700000000)+number(12,123456789012345678)

class ReceiveTests(unittest.TestCase):
    def test_large_identity_and_sender_extraction(self):
        event=decode_add_message(sample(),'123456@chatroom','WXRECV1006')
        self.assertEqual(event['id'],'123456789012345678')
        self.assertEqual(event['sender_id'],'wxid_M')
        self.assertEqual(event['content'],'WXRECV1006')
    def test_wrong_room_outbound_and_marker_are_rejected(self):
        for payload in (sample(room='999@chatroom'),sample(room='wxid_bot',receiver='123456@chatroom'),sample(text='other')):
            with self.assertRaises(DecodeError):decode_add_message(payload,'123456@chatroom','WXRECV1006')
    def test_wire_limits_duplicates_and_truncation(self):
        cases=[b'\x80',b'\x0a\xff\xff\xff\x7f',b'\x00',b'\x08'+b'\xff'*10,
               sample()+string(2,'123456@chatroom'),b'x'*16385]
        for payload in cases:
            with self.assertRaises(DecodeError):decode_add_message(payload,'123456@chatroom','WXRECV1006')
    def test_native_layout(self):
        self.assertEqual(ctypes.sizeof(Config),200)
        self.assertEqual(ctypes.sizeof(State),72)
        self.assertEqual(ctypes.sizeof(Slot),16416)
        self.assertEqual(ctypes.sizeof(Command),16)
        self.assertEqual(Slot.payload.offset,32)
if __name__=='__main__':unittest.main()
