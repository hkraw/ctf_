from pwn import *
from Crypto.Util.number import *

module = ELF('./libflaggen-f2c2f9306bdbae9522d200db5bd9f55d.so')

start_state = 0x2122DF7763817B1D

enc_flag = 0xEF6422F8CCD8CB66C60395F7F7CB0C2435D6CDCB1D29466A5235CBE76611A25F5357E1A50BD24C434908DAC4026C2CC1FD286F2F7952EFBFEE9990419F5F652164D88AF5371C1945F107
fflag = long_to_bytes(enc_flag)
lfsr = long_to_bytes(0x2122DF7763817B1D)
d = ''
v2 = 0
while len(fflag) > v2:
	for i in range(5):
		v4 = ord(chr(lfsr[i]))
		v5 = 0
		while v5 != i:
			v6 = v4
			v4 = v4 >> 1
			v7 = v4
			if (v6&1):
				v7 = v4 ^ 0xb400
				v4 = v7
			v5 += 1
		d += chr(v4)
	while lfsr[10] != v9[0]:
		v10 = ord(v9[1])
		v9 = v9[1: ]
		v11 = v10
		v11 = v10 >> 1
		v8 ^= (2 * v10) ^ v10 ^ v11
	v12 = ord(fflag[v2])
	v2 += 1
	print(chr(v12 ^ v8),end='')
