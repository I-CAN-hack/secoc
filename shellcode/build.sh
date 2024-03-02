#!/usr/bin/env bash
set -e

v850-elf-gcc -fPIC -ffreestanding -c main.c -o main.o
v850-elf-objcopy -O binary -j .text main.o main.bin
