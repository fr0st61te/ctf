#!/usr/bin/env python3

a = [0x69, 0x71, 0x67, 0x70, 0x5f, 0x6f, 0x60, 0x74, 0x65, 0x60, 0x59, 0x67, 99, 0x66, 0x61, 0x57, 100, 0x4e, 0x65, 0x5c, 0x5e, 0x4f, 0x49, 0x4a, 0x5c, 0x46, 0x4e, 0x54, 0x51, 0x48, 0x1c, 0x5e]
res = ""
print(len(a))

for i in range(32):
    print(i)
    print(chr(a[i] + i))
    res += chr(a[i] + i)
print(res)
