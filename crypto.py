from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from hmac import compare_digest
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE=16
pad=lambda s: s+((BLOCK_SIZE-len(s)%BLOCK_SIZE)*chr(BLOCK_SIZE-len(s)%BLOCK_SIZE)).encode()
unpad = lambda s : s[:-ord(s[len(s)-1:])]

COUNT=5000

def str2key(str, salt=None, count=COUNT):
	if not salt: salt=Random.new().read(BLOCK_SIZE)
	keys=PBKDF2(str, salt,  dkLen=32, count=count, prf=lambda password, salt: HMAC.new(password, salt, SHA256).digest())
	return salt, keys[:16], keys[16:]

def encrypt(data, key):
	
	if not len(data):
		print('no data to encrypt!')
		return None
	if not len(key):
		print('no encryption key!')
		return None
	
	salt, key1, key2=str2key(key)
	
	data=pad(data)
	iv=Random.new().read(BLOCK_SIZE)
	aes=AES.new(key1, AES.MODE_CBC, iv)
	
	ct=iv+aes.encrypt(data)
	
	return str(COUNT).encode()+b'#'+salt+HMAC.new(key2, ct, SHA256).digest()+ct

def decrypt(data, key):
	
	if not len(data):
		print('no data to decrypt!')
		return None
	if not len(key):
		print('no decryption key!')
		return None
	
	count, data=data.split(b'#', 1)
	
	count=int(count)
	
	salt=data[:16]
	
	salt, key1, key2=str2key(key, salt, count)
		
	hmac1=data[16:48]
	ct=data[48:]
	
	if not compare_digest(HMAC.new(key2, ct, SHA256).digest(), hmac1):
		print('hmac verification failed!')
		return None
	
	iv=ct[:BLOCK_SIZE]
	aes=AES.new(key1, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ct[BLOCK_SIZE:]))
