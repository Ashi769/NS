from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hmac
import hashlib
import binascii
import random


p = int("de9b707d4c5a4633c0290c95ff30a605aeb7ae864ff48370f13cf01c49adb9f23d19a439f743ee7703cf342d87f431105c843c78ca4df639931f3458fae8a94d1687e99a76ed99d0ba87189f42fd31ad8262c54a8cf5914ae6c28c540d714a5f6087a172fb74f4814c6f968d72386ef345a05180c3b3c7ddd5ef6fe76b0531c3", 16)
g = 2
bit_size = 1024
keylen = 256
max_keylen = 1024
cipher_suite = {0: "TLS_RSA_WITH_NULL_MD5",
               1: "TLS_RSA_WITH_NULL_SHA",
               2: "TLS_RSA_EXPORT_WITH_RC4_MD5",
               3: "TLS_DH_annon_WITH_RC4_128_MD5",
               4: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
               5: "TLS_RSA_WITH_RC4_128_SHA"
               }


def ClientHello(version, suite, shared_secret, client_random, session_ID):
    print('\nClientHello\n\n')
    print('---------------------------------BEGIN-------------------------------------\n')
    print(f'\nversion: {version}')
    print(f'\nCipher_Suite: {cipher_suite[suite]}')
    print(f'\nClient_Random: {hex(client_random)}\n')
    print(f'\nSecret Key: {shared_secret}\n')
    print(f'\nSession ID: {session_ID}\n')
    print('---------------------------------END-------------------------------------\n')
    
def ServerHello(version, suite):
    print('\nServerHello\n\n')
    print('---------------------------------BEGIN-------------------------------------\n')
    print(f'\nversion: {version}')
    print(f'\nCipher_Suite_selected: {cipher_suite[suite]}')
    print(f'\nServer_Random: {hex(server_random)}\n')
    print(f'\n\n\nPre Master secret:{hex(Bob_calc_key)}')
    print(f'\n\n\nMaster secret:{master_secret}')
    print(f'\nclient_write_MAC_key: {client_write_MAC_key}\n')
    print(f'\nserver_write_MAC_key: {client_write_MAC_key}\n')
    print(f'\nclient_write_key: {client_write_key}\n')
    print(f'\nserver_write_key: {server_write_key}\n')
    print('---------------------------------END-------------------------------------\n')
    
def prf(secret,label,seed,numblocks):
    seed=b'{label+seed}'
    output = '' 
    a = hmac.new(b'{secret}',msg=seed,digestmod=hashlib.sha256).hexdigest()
    a = a.encode("utf-8")
    for  j in range(numblocks): 
        output += hmac.new(b'{secret}',msg=a+seed,digestmod=hashlib.sha256).hexdigest()
        a=hmac.new(b'{secret}',msg=a,digestmod=hashlib.sha256).hexdigest()
        a = a.encode("utf-8")
    return output 

def master_secret(pms,client_random,server_random):
    out=prf(b'{pms}',"master secret",client_random+server_random,2) 
    return out[:48] 


def keyblock(ms,client_random,server_random):
    u=prf(ms,"key expansion",server_random+client_random,4)
    return (u[:20],u[20:40],u[40:72],u[72:104]) 


def expo(a, b):
    if b == 1:
        return a%p
    if b % 2 == 0:
        k = expo(a, b//2)
        return (k*k)%p
    else:
        k = expo(a, (b-1)//2)
        return ((k*k)%p *(a%p))%p             
    
def getKey():        
    k = random.randint(keylen, keylen)
    a = random.getrandbits(k)
    if (a >= p):
        a = p - 1
    c = expo(g, a)
    return (c, a)

def getPrivateKey(key, a):
    return expo(key, a)

suite = 4
version ="3.1"
(Alice_key, a) = getKey()
client_random = random.getrandbits(random.randint(keylen, keylen))
session_ID = random.getrandbits(random.randint(32, 32))

Alice_keyPair = RSA.generate(3072)
Alice_pubKey = Alice_keyPair.publickey()
pubKeyPEM = Alice_pubKey.exportKey()
privKeyPEM = Alice_keyPair.exportKey()
ClientHello(version, suite, Alice_key,client_random, session_ID)



Bob_keyPair = RSA.generate(3072)
Bob_pubKey = Bob_keyPair.publickey()
pubKeyPEM = Bob_pubKey.exportKey()
server_random = random.getrandbits(random.randint(keylen, keylen))
privKeyPEM = Bob_keyPair.exportKey()


print('-------------------------------------Master Secret Calculation BEGIN-------------------------------------\n')
msg = bytes(f'{Alice_key}', 'utf-8')
encryptor = PKCS1_OAEP.new(Bob_pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted shared secret by the client:", binascii.hexlify(encrypted).decode("utf-8"))


decryptor = PKCS1_OAEP.new(Bob_keyPair)
decrypted = decryptor.decrypt(encrypted)
Bob_calc_key =  decrypted.decode("utf-8")
print('\n\n\nDecrypted shared secret by the server:', Bob_calc_key)

print('-------------------------------------Master Secret Calculation END-------------------------------------\n')

(Bob_key, b) = getKey()
Bob_calc_key = getPrivateKey(int(Bob_calc_key), b)

master_secret = master_secret(str(Bob_calc_key), str(client_random), str(server_random))
(client_write_MAC_key, server_write_MAC_key, client_write_key, server_write_key) = keyblock(master_secret, client_random, server_random)

ServerHello(version, suite)
