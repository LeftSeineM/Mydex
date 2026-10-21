"""Validate parsing with artificial memory; never opens WeChat or any process."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent/'research'))
from locate_external_marker import msvc_bytes
from external_reader import Reader,Region
from run_native_observer import Config,State
import ctypes

class Memory:
    def __init__(self,blocks):self.blocks=blocks;self.reads=[]
    def read(self,address,size):
        self.reads.append((address,size))
        value=self.blocks.get(address)
        if value is None or len(value)<size:raise OSError('unmapped test memory')
        return value[:size]

class ExternalReaderTests(unittest.TestCase):
    def test_sso_marker(self):
        marker=b'WXPAIR1006'
        memory=Memory({0x10000:marker.ljust(16,b'\0')+struct.pack('<QQ',len(marker),15)})
        self.assertEqual(msvc_bytes(memory,0x10000,64,len(marker)),marker)

    def test_heap_string(self):
        marker=b'long_marker_for_heap_storage'
        memory=Memory({0x10000:struct.pack('<QQQQ',0x20000,0,len(marker),31),0x20000:marker})
        self.assertEqual(msvc_bytes(memory,0x10000,64,len(marker)),marker)

    def test_length_mismatch_does_not_follow_pointer(self):
        memory=Memory({0x10000:struct.pack('<QQQQ',0xdeadbeef,0,50,63)})
        self.assertIsNone(msvc_bytes(memory,0x10000,64,9))
        self.assertEqual(memory.reads,[(0x10000,32)])

    def test_capacity_corruption_rejected(self):
        memory=Memory({0x10000:struct.pack('<QQQQ',0xdeadbeef,0,20,15)})
        self.assertIsNone(msvc_bytes(memory,0x10000,64))

    def test_unmapped_pointer_raises_for_caller_to_skip(self):
        memory=Memory({0x10000:struct.pack('<QQQQ',0x20000,0,20,31)})
        with self.assertRaises(OSError):msvc_bytes(memory,0x10000,64,20)

    def test_read_only_access_and_native_abi_sizes(self):
        self.assertEqual(Reader.ACCESS,0x410)
        self.assertEqual(ctypes.sizeof(Region),48)
        self.assertEqual(ctypes.sizeof(Config),80)
        self.assertEqual(ctypes.sizeof(State),176)
        self.assertEqual(State.room.offset,48)

if __name__=='__main__':unittest.main()
