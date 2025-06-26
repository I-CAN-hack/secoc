#!/usr/bin/env python3
import struct
import argparse

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

from openpilot.tools.lib.route import Route
from openpilot.tools.lib.logreader import LogReader

KEY_LEN = 16

def build_sync_mac(key, trip_cnt, reset_cnt, id_=0xf):
  id_ = struct.pack('>H', id_) # 16
  trip_cnt = struct.pack('>H', trip_cnt) # 16
  reset_cnt = struct.pack('>I', reset_cnt << 12)[:-1] # 20 + 4 padding

  to_auth = id_ + trip_cnt + reset_cnt # SecOC 11.4.1.1 page 138

  cmac = CMAC.new(key, ciphermod=AES)
  cmac.update(to_auth)

  msg = "0" + cmac.digest().hex()[:7]
  msg = bytes.fromhex(msg)
  return struct.unpack('>I', msg)[0]


def find_key(data, sync_msg):
    trip_cnt = struct.unpack('>H', sync_msg[:2])[0]
    reset_cnt = struct.unpack('>I', b'\x00' + sync_msg[2:5])[0] >> 4
    good_mac = struct.unpack('>I', sync_msg[4:])[0] & 0xfffffff

    for offset in range(len(data) - KEY_LEN + 1):
        key = data[offset:offset + KEY_LEN]
        mac = build_sync_mac(key, trip_cnt, reset_cnt)

        if mac == good_mac:
            print(f"Found key {key.hex()}, offset 0x{offset:x}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("route", help="Route to check")
    parser.add_argument("dataflash", help="Filename to dataflash dump")
    args = parser.parse_args()

    route = Route(args.route)
    logs = [s for s in route.log_paths() + route.qlog_paths() if s is not None]

    with open(args.dataflash, 'rb') as f:
        data = f.read()

    sync_msg_seen = False
    for path in logs:
        log = LogReader(path)

        for msg in log:
            if msg.which == 'can':
                for c in msg.can:
                    if c.src == 0 and c.address == 0xf:
                        print("Sync Msg", c.dat.hex())
                        find_key(data, c.dat)
                        sync_msg_seen = True

    if not sync_msg_seen:
        print("Warning: No SecOC Synchronization message in route")
