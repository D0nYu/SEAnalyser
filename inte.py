from pwn import *
import time
context.log_level = 'debug'

if __name__ == '__main__':
	p = remote("pwnable.kr",9008)
	p.recvuntil("Ready? starting in 3 sec ...")
	time.sleep(3)
	p.recvline()

	p.send("0 1-1 2")
	p.interactive()