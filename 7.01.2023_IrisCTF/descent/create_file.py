#!/usr/bin/env python

a = "4096\n" + 4096 * "A" + "\n"
o = open("test", "a")
o.write(a)
o.close()
