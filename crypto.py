from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from hmac import compare_digest
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE=16
pad=lambda s: s+((BLOCK_SIZE-len(s)%BLOCK_SIZE)*chr(BLOCK_SIZE-len(s)%BLOCK_SIZE)).encode()
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def str2key(str, salt=None):
	if not salt: salt=Random.new().read(BLOCK_SIZE)
	return salt, PBKDF2(str, salt, prf=lambda password, salt: HMAC.new(password, salt, SHA256).digest())

def encrypt(data, key):
	
	if not len(data):
		print('no data to encrypt!')
		return None
	if not len(key):
		print('no encryption key!')
		return None
	
	salt, key=str2key(key)
	
	data=pad(data)
	iv=Random.new().read(BLOCK_SIZE)
	aes=AES.new(key, AES.MODE_CBC, iv)
	
	ct=iv+aes.encrypt(data)
	
	key2=SHA256.new(key).digest()
	
	return salt+HMAC.new(key2, ct, SHA256).digest()+ct

def decrypt(data, key):
	
	if not len(data):
		print('no data to decrypt!')
		return None
	if not len(key):
		print('no decryption key!')
		return None
	
	salt=data[:16]
	
	salt, key=str2key(key, salt)
		
	hmac1=data[16:48]
	ct=data[48:]
	
	key2=SHA256.new(key).digest()
	
	if not compare_digest(HMAC.new(key2, ct, SHA256).digest(), hmac1):
		print('hmac verification failed!')
		return None
	
	iv=ct[:BLOCK_SIZE]
	aes=AES.new(key, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ct[BLOCK_SIZE:]))
