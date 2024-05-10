## SecOC Key Extractor

This repository contains scripts to extract SecOC keys. See the related [blog post](https://icanhack.nl/blog/secoc-key-extraction/) for more details. Confirmed working by users on the following vehicles:
 - 2021 RAV4 Prime
 - 2023 RAV4 Prime XSE
 - 2021 Sienna LE


## Read this first
 - THIS IS AT YOUR OWN RISK
 - This may brick your EPS. Only attempt this if you're willing to replace the EPS or steering rack if needed.
 - A comma.ai panda is needed to communicate over CAN, and the latest panda python library needs to be installed (pip install -r requirements.txt).

## Extracting Keys

With the vehicle completely off and the brake pedal not pressed, press the power button twice to get the car into "IGNITION ON" without the green `[READY]` light also being on. You can then run the script. Example:

```bash
$ ./extract_keys.py
Getting application versions...
 - APPLICATION_SOFTWARE_IDENTIFICATION (application) b'\x018965B4209000\x00\x00\x00\x00'
 - APPLICATION_SOFTWARE_IDENTIFICATION (bootloader)  b'\x01!!!!!!!!!!!!!!!!'

Security Access...
 - SEED: e8c0f91e28faee7b1fc04d49e707fd3e
 - KEY: ad250d24bf843f8d831eaa8bb78e7839
 - Key OK!

Preparing to upload payload...
 - Write data by identifier 0x201 00000000000000000000000000000000
 - Write data by identifier 0x202 00000000000000000000000000000000

Upload payload...
 - Request download
 - Transfer data 0
 - Transfer data 1
 - Transfer data 2
 - Transfer data 3

Verify payload...
 - Routine control 0x10f0 OK!

Trigger payload...

Dumping keys...
100%|█████████████████████████████████████████████████| 448/448 [00:00<00:00, 15230.75it/s]

ECU_MASTER_KEY    9432d3638b842d75e64db091fce5fa68
SecOC Key (KEY_4) c5fc900668d068ec39695d9a8885be2d
```


## Building a payload
This step is not necessary to extract the keys, as a pre-built payload is included in the repository.

The shellcode can be found in `shellcode/main.c`. The folder also contains scripts and Dockerfiles needed to build a cross compiler and compile the code. Run `./build_docker.sh` to do this automatically.

After compiling the shellcode the payload has to be built. This can be done using the `build_payload.py` script. The script needs a secret from the firmware to derive the encryption key. Obtaining this key is left as [an exercise to the reader](https://icanhack.nl/blog/rh850-glitch/).

```bash
./build_payload.py -s "ffffffffffffffffffffffffffffffff" shellcode/main.bin
```
