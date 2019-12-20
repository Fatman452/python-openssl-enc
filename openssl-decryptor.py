from hashlib import md5
from Crypto.Cipher import AES, DES3
from Crypto import Random
import binascii as basc

class OpenSSLDecrypt(object):
    def __init__(self, password):
        self.password = password
        self.ALGS = {
            'AES' : AES,
            'DES3' : DES3
        }

    def __derive_key_and_iv(self, salt, key_length, iv_length):
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + self.password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    def __getCipherAlgortihmInstance(self, CIPHER_ALG, salt, key_length, bs):

        key, iv = self.__derive_key_and_iv(salt, key_length, bs)
        cipher = CIPHER_ALG.new(key, CIPHER_ALG.MODE_CBC, iv)
        return cipher

    def decrypt(self, CIPHER_ALG_NAME, in_file, out_file, key_length=32):
        CIPHER_ALG = self.ALGS[CIPHER_ALG_NAME]
        bs = CIPHER_ALG.block_size
        
        #get salt from openssl encrypted file
        header = in_file.read(bs)
        magic_len = len('Salted__')
        salt = header[magic_len:]
        
        cipher = self.__getCipherAlgortihmInstance(CIPHER_ALG, salt, key_length, bs)
        # plaintext = cipher.decrypt(ciphertext[magic_len + len(salt):])
        # out_file.write(plaintext.replace(b'\x01', b''))
        next_chunk = b''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                print(chunk)
                padding_length = ord(chr(chunk[-1]))

                if padding_length < 1 or padding_length > bs:
                    raise ValueError("bad decrypt pad (%d)" % padding_length)
                if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                    raise ValueError("bad decrypt")
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)

    def encrypt(self, CIPHER_ALG_NAME, in_file, out_file, key_length=32):
        CIPHER_ALG = self.ALGS[CIPHER_ALG_NAME]
        bs = CIPHER_ALG.block_size

        #generate salt for encryption
        magin_len = len('Salted__')
        salt = Random.new().read(bs - magic_len)

        cipher = self.__getCipherAlgortihmInstance(CIPHER_ALG, salt, key_length, bs)
        
        out_file.write(b'Salted__' + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = bs - (len(chunk) % bs)
                chunk += padding_length * chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))

tool = OpenSSLDecrypt(b'123')
with open('hola.enc', 'rb') as a, open('test-class.txt', 'wb') as b:
    tool.decrypt('DES3', a, b, 24)
