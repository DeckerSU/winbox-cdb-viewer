"""Generate synthetic CDB inputs using only the Python standard library.

JSON and TXT files are reviewed reference outputs, maintained separately.
Run this script from any directory; output stays in tests/fixtures.
"""
from pathlib import Path
import struct
import hashlib

PLAIN = 0xc01df00d
ENCRYPTED = 0x4011f00d

def _rc4(data, key):
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 255
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for n in range(768 + len(data)):
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        state[i], state[j] = state[j], state[i]
        key_byte = state[(state[i] + state[j]) & 255]
        if n >= 768:
            output.append(data[n - 768] ^ key_byte)
    return bytes(output)

root=Path(__file__).parent/'fixtures'
def u32(n): return struct.pack('<I',n)
def s(n,b): return u32(0x21000000|n)+bytes([len(b)])+b
child=b'M2'+s(1,b'nested (not an address)')
message=b'M2'+s(1,b'192.0.2.1')+s(2,b'guest')+s(3,b'synthetic-only')+s(4,b'legacy')+s(8,b'Lab')+s(11,b'agent')+s(12,b'workspace')+s(0xfe0009,'Example text'.encode())+u32(0x01000007)+u32(0x08fe0001)+u32(7)
message+=s(0x999,b'first')+s(0x999,b'second')+s(0x04000001,b'bit26')+s(2,b'\xff')
message+=u32(0x09000001)+b'\x05'+u32(0x10000002)+struct.pack('<Q',2**64-1)+u32(0x18000003)+bytes(range(16))
message+=u32(0x2b000020)+bytes([len(child)])+child+u32(0x32000021)+u32(3)+b'raw'
for code,payload in [(0,b'\0\1'),(8,u32(0)+u32(2**32-1)),(16,struct.pack('<QQ',0,2**64-1)),(24,bytes(range(32))),(32,b'\x01\0a\x01\0b'),(40,struct.pack('<H',len(child))+child+b'\0\0'),(48,b'\x01\0a\x01\0\xff')]:
    message+=u32(((code|0x80)<<24)|0x30)+b'\x02\0'+payload
message+=u32(0xa3000031)+u32(2)+u32(1)+b'x'+u32(1)+b'y'
plain=u32(PLAIN)+u32(len(message))+message+u32(0)+u32(2)+b'M2'
salt=bytes(range(32));password=' passphrase😀 '
enc=u32(ENCRYPTED)+salt+_rc4(plain,hashlib.sha1(salt+password.encode()).digest())
for name,data,pw in [('plain',plain,None),('encrypted',enc,password),('empty-encrypted',u32(ENCRYPTED)+salt+_rc4(u32(PLAIN),hashlib.sha1(salt).digest()),'')]:
    (root/f'{name}.cdb').write_bytes(data)
