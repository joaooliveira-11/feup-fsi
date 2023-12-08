# CTF Semana #10 (Weak Encryption)

For this ctf, we first start by looking into the provided file:

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEYLEN = 16

def gen(): 
	offset = 3 # Hotfix to make Crypto blazing fast!!
	key = bytearray(b'\x00'*(KEYLEN-offset)) 
	key.extend(os.urandom(offset))
	return bytes(key)

def enc(k, m, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	encryptor = cipher.encryptor()
	cph = b""
	cph += encryptor.update(m)
	cph += encryptor.finalize()
	return cph

def dec(k, c, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	decryptor = cipher.decryptor()
	msg = b""
	msg += decryptor.update(c)
	msg += decryptor.finalize()
	return msg
```

We can easily see that in the 'gen()' algorithm, only the three final bytes are generated randomly.

This is very important since it can be vulnerable to brute force attacks. If we try to change only the last 3 bytes in each try, we can obtain the ctf flag.

For this, we will connect to the server, where we can get the nonce and cyphertext:

```
nonce: 0ab5e6e7f69d0cc702cbce68f7ea36c9
ciphertext: 43a234c7331be64a94050050db9e3597cbdc8a49e8f5ae16ccce6959d8d5a0edd7b91d6f235031
```
![cypher_nonce](../docs/week10/cipher_nonce.png)

Now, we will perform a brute force attack, where we will only change the last 3 bytes and after we decipher the message, we will check if the first 4 bytes are equal to "flag" since the flags in ctfs start like this. If so, we print it.

For that, we created a for cycle where we will test every possibilite of values from the last 3 bytes. Since each byte has 8 bits, we will have 2 ^24 possible combinations which is a lot.

Our final script is the following:





![script_error](../docs/week10/script_error.png)



Finally, we got the flag:
![flag](../docs/week10/flag.png)