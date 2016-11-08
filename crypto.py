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
	
	if algo=='AES-128': block_size=16
	else: block_size=32
	
	salt, key1, key2=str2key(key, block_size=block_size)
	
	data=pad(data, block_size)
	iv=Random.new().read(AES.block_size)
	aes=AES.new(key1, AES.MODE_CBC, iv)
	
	ct=iv+aes.encrypt(data)
	
	return str(block_size).encode()+b'#'+str(COUNT).encode()+b'#'+str(SALT_LEN).encode()+b'#'+salt+HMAC.new(key2, ct, SHA256).digest()+ct

def decrypt(data, key):

	try:
		block_size, count, salt_len, data=data.split(b'#', 3)
		count=int(count)
		block_size=int(block_size)
		salt_len=int(salt_len)
	except Exception as e:
		print('--------------------\n'+str(e)+'\n--------------------')
		return None, 'Seems the structure of the file\ndoes not conform to an encrypted file!'
	
	salt=data[:salt_len]
	
	salt, key1, key2=str2key(key, salt, count, block_size=block_size)
		
	hmac1=data[salt_len:salt_len+HMAC_LEN]
	ct=data[salt_len+HMAC_LEN:]
	
	if not compare_digest(HMAC.new(key2, ct, SHA256).digest(), hmac1):
		print('hmac verification failed!')
		return None, 'HMAC verification failed!'
	
	iv=ct[:AES.block_size]
	aes=AES.new(key1, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ct[AES.block_size:])), ''
