from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from hmac import compare_digest
from Crypto.Protocol.KDF import PBKDF2

#------------------------------

COUNT=1000 #PBKDF2  repeat count

SALT_LEN=16 #PBKDF2  salt length

HMAC_LEN=32 #HMAC output length (currently, changing this needs code changes)

#------------------------------

pad=lambda s, block_size: s+((block_size-len(s)%block_size)*chr(block_size-len(s)%block_size)).encode()
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def str2key(str, salt=None, count=COUNT, block_size=16):
	if not salt: salt=Random.new().read(SALT_LEN)
	keys=PBKDF2(str, salt,  dkLen=block_size*2, count=count, prf=lambda password, salt: HMAC.new(password, salt, SHA256).digest())
	return salt, keys[:block_size], keys[block_size:]

def encrypt(data, key, algo):
	
	if not len(data):
		print('no data to encrypt!')
		return None
	if not len(key):
		print('no encryption key!')
		return None
	
	if algo=='AES-128': block_size=16
	else: block_size=32
	
	print('block_size:', block_size)
	
	salt, key1, key2=str2key(key, block_size=block_size)
	
	data=pad(data, block_size)
	iv=Random.new().read(AES.block_size)
	aes=AES.new(key1, AES.MODE_CBC, iv)
	
	ct=iv+aes.encrypt(data)
	
	return str(block_size).encode()+b'#'+str(COUNT).encode()+b'#'+salt+HMAC.new(key2, ct, SHA256).digest()+ct

def decrypt(data, key):
	
	if not len(data):
		print('no data to decrypt!')
		return None
	if not len(key):
		print('no decryption key!')
		return None
	
	block_size, count, data=data.split(b'#', 2)
	
	count=int(count)
	block_size=int(block_size)
	
	salt=data[:SALT_LEN]
	
	salt, key1, key2=str2key(key, salt, count, block_size=block_size)
		
	hmac1=data[SALT_LEN:SALT_LEN+HMAC_LEN]
	ct=data[SALT_LEN+HMAC_LEN:]
	
	if not compare_digest(HMAC.new(key2, ct, SHA256).digest(), hmac1):
		print('hmac verification failed!')
		return None
	
	iv=ct[:AES.block_size]
	aes=AES.new(key1, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ct[AES.block_size:]))
