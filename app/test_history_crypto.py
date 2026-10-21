import hashlib
import hmac
import os
from pathlib import Path
import sys
import unittest
from Crypto.Cipher import AES
sys.path.insert(0,str(Path(__file__).resolve().parent/'research'))
from history_crypto import decrypt_page,verify_page,hmac_key,dpapi
class CryptoTests(unittest.TestCase):
    def test_authenticated_page_and_tampering(self):
        key=b'K'*32;salt=b'S'*16;iv=b'I'*16
        plain=b'\x10\x00\x02\x02\x50'+b'P'*3995
        ciphertext=AES.new(key,AES.MODE_CBC,iv).encrypt(plain)
        tag=hmac.new(hmac_key(key,salt),ciphertext+iv+(1).to_bytes(4,'little'),'sha512').digest()
        page=salt+ciphertext+iv+tag
        self.assertTrue(verify_page(page,1,key,salt))
        self.assertEqual(decrypt_page(page,1,key,salt),b'SQLite format 3\0'+plain+b'\0'*80)
        self.assertFalse(verify_page(page,2,key,salt))
        self.assertFalse(verify_page(page,1,b'X'*32,salt))
        damaged=bytearray(page);damaged[99]^=1
        with self.assertRaises(ValueError):decrypt_page(bytes(damaged),1,key,salt)
    def test_dpapi_current_user_round_trip(self):
        value=os.urandom(128);protected=dpapi(value)
        self.assertNotIn(value,protected)
        self.assertEqual(dpapi(protected,True),value)
if __name__=='__main__':unittest.main()
