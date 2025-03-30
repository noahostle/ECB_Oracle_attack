import time
import requests
import string
import sys


"""

The vulnerable example implementation uses ECB mode to encrypt a flag.
If we send it some input, it will add the flag to the end of it, and then encrypt it.

eg. Input:	00
    Flag:	01 23 45
    Server:   E(00 01 23 45)

This is an issue since when the same plaintext is encrypted with ECB, it results in
the same ciphertext.

Since we have an oracle (we can send the web server some data and it will encrypt it),
we can bruteforce the plaintext byte by byte.

This works since we can send the server some input that is one byte under the ciphers
block size. The server will then append the flag to our input, and encrypt that block.


Eg. Block Size:	4 bytes
    Flag:	01 23 45
    Input: 	00 00 00
    Server:   E(00 00 00 01) + E(23 45) 

Since in ECB, each block is encrypted without any initialisation vector, or any XOR
with the previous block for example, E(00 00 00 01) will always result in the exact
same ciphertext every time it is encrypted with the same key.

We can now exploit this by sending a whole block, with a guess as the the first byte
of the flag at the end. If we get our guess right, we should see the exact same
ciphertext as when we sent one byte less than a whole block;

Eg. Flag:       01 23 45
    Input:      00 00 00 00
    Server:   E(00 00 00 00) + E(01 23 45)

    ciphertext != our encrypted 3 byte guess -> our guess was wrong

    Input:	00 00 00 01
    Server:   E(00 00 00 01) + E(01 23 45)

    ciphertext == our 3 bytes guess -> the first byte of flag is 01

We can then decrease our padding, and add our known bytes when we take our guesses,
and iterate until we recover the whole flag;

Eg. Flag:       01 23 45
    Known:	01 ?? ??

    Input:      00 00
    Server:   E(00 00 01 23) + E(45)


    Input:	00 00 01 00
    Server:   E(00 00 01 00) + E(01 23 45)

    ciphertext != encrypted guess
	
    ... 

    Input:	00 00 01 23
    Server:   E(00 00 01 23) + E(01 23 45)

    ciphertext == guess! -> the next byte of the flag is 23

    and so on...


This issue is fixed in modes such as CBC as long as an IV is used, since we cannot
compare the output of the ciphers - they will always be different, even for the same
inputs!

"""






BASE_URL = "http://aes.cryptohack.org/ecb_oracle"


def endpoint(uri, data=[]):
	return requests.get(f"{BASE_URL}/{uri}/{'/'.join(data)}").json()
	

def visualize(hexstring):
	byte = [hexstring[i:i+2] for i in range(0, len(hexstring), 2)]
	for i in range(0, len(byte), 16):
		print(f"BLOCK {i//16+1} : "+" ".join(byte[i:i+16]))	

def brute(known=''):
	
	flag = known.encode().hex()
	#16 byte blocksize
	padding = 31-len(known)
	alphabet = [format(ord(_), 'x') for _ in string.printable]

	while True:
		
		print(f"[+] Bytes Recovered : {bytes.fromhex(flag).decode('ascii')}\n")
		payload = padding*'00'
		
		print("[+] PLAINTEXT (?? = the byte we are guessing) : ")
		visualize(payload+flag+"??")

		trueblock = endpoint('encrypt', [payload])['ciphertext'][0:64]	
		print("[+] CIPHERTEXT :")
		visualize(trueblock)
		print('\n'*9)

		for x in alphabet:
			
			testblock = endpoint('encrypt', [payload+flag+x])['ciphertext'][0:64]
			
			sys.stdout.write('\033[F\033[K'*9)
			print("[/] GUESS PLAINTEXT : ")
			visualize(payload+flag+x)
			
			print("[/] GUESS CIPHERTEXT : ")
			visualize(testblock)
			
			if trueblock==testblock:
				flag+=x
				if chr(int(x,16))=='}':
					return flag
				padding-=1
				print("\n\n[!] Our guess matches!")
				time.sleep(5)
				sys.stdout.write('\033[F\033[K'*18)
				break
			print("\n\n[-] Our encrypted guess does not match the Ciphertext.")

print(f"[!] cracked! : {brute('crypto{')}")
