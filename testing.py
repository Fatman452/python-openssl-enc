from hashlib import md5
from Crypto.Cipher import AES, DES3
from Crypto import Random
import binascii as basc


def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)

def decrypt(CIPHER_ALG, in_file, out_file, password, key_length=32, iv_length=16):
    bs = CIPHER_ALG.block_size
    ciphertext = in_file.read()
    magic_len = len('Salted__')
    salt = ciphertext[magic_len:magic_len+bs]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = CIPHER_ALG.new(key, CIPHER_ALG.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[len('Salted__') + len(salt):])
    out_file.write(plaintext.replace(b'\x01', b''))
    #next_chunk = b''
    # finished = False
    # while not finished:
    #     chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
    #     if len(next_chunk) == 0:
    #         padding_length = chunk[-1]
    #         print(padding_length)
    #         chunk = chunk[:-padding_length]
    #         finished = True
    #     print(next_chunk)
    #     out_file.write(chunk)
    out_file.close()
    in_file.close()


a = open('hola.enc', 'rb')
b = open('hola-generado-python.txt', 'wb')
decrypt(DES3, a, b, b'123', 24, 8)

