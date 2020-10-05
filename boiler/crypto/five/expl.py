from pwn import *
from past.builtins import xrange
from time import sleep
from base64 import *
from string import *
from codecs import decode

lookup = {'A':'aaaaa', 'B':'aaaab', 'C':'aaaba', 'D':'aaabb', 'E':'aabaa', 
        'F':'aabab', 'G':'aabba', 'H':'aabbb', 'I':'abaaa', 'J':'abaab', 
        'K':'ababa', 'L':'ababb', 'M':'abbaa', 'N':'abbab', 'O':'abbba', 
        'P':'abbbb', 'Q':'baaaa', 'R':'baaab', 'S':'baaba', 'T':'baabb', 
        'U':'babaa', 'V':'babab', 'W':'babba', 'X':'babbb', 'Y':'bbaaa', 'Z':'bbaab'}

lookup_table = {'A' : 'Z', 'B' : 'Y', 'C' : 'X', 'D' : 'W', 'E' : 'V', 
        'F' : 'U', 'G' : 'T', 'H' : 'S', 'I' : 'R', 'J' : 'Q', 
        'K' : 'P', 'L' : 'O', 'M' : 'N', 'N' : 'M', 'O' : 'L', 
        'P' : 'K', 'Q' : 'J', 'R' : 'I', 'S' : 'H', 'T' : 'G', 
        'U' : 'F', 'V' : 'E', 'W' : 'D', 'X' : 'C', 'Y' : 'B', 'Z' : 'A'}

def bacon(ciphertext):
	d = []
	text = ''
	for i in range(len(ciphertext)):
		text += str(chr(ciphertext[i]))
		if (i+1)%5 == 0: d.append(text.lower()); text = ''
	fuck = ''
	for each in d: 
		for _ in lookup:
			if each == lookup[_]: fuck += _
	return fuck
				
def rot13(ciphertext):
	return decode(str(ciphertext),'rot_13')

def atbash(message): 
    cipher = '' 
    for letter in message: 
        # checks for space 
        if(letter != ' '):
            #adds the corresponding letter from the lookup_table 
            cipher += lookup_table[letter] 
        else: 
            # adds space 
            cipher += ' '
  
    return cipher

if __name__ == '__main__':
	io = remote('chal.ctf.b01lers.com',2008)
	while True:
		io.recvuntil('Method: ')
		method = io.recvline().strip()
		io.recvuntil('Ciphertext: ')
		cipher = io.recvline().strip()
		if method == b'bacon':
			plain = bacon(cipher)
			print(plain)
			io.sendlineafter(': ',plain.lower())
		elif method == b'rot13':
			plain = rot13(cipher)
			io.sendlineafter(': ',plain[2:-1])
		elif method == b'Base64':
			plain = b64decode(cipher)
			io.sendlineafter(': ',plain)
		elif method == b'atbash':
			plain = atbash(str(cipher).replace('b\'','').replace('\'','').upper())
			io.sendlineafter(': ',plain.lower())
	io.interactive()
