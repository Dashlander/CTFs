import random
import time
import tqdm
from binascii import unhexlify
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

public_message = b'I am about to send something very secret. Please pay close attention'
encrypted_public_message = b'CzNUxzyzGWHsoFvp49gYrlucE1gX5IxiouF5siJjSpASDM5GSil9oYYa/5Z8scfK8P3HW8reCykJVw58E8OSbjAb59IpYApxjOQbGk8sa6anLCl/4HVvdR05tLakhHyr'
flag = b'IUShVotCVlgw2xPXa1glLdrXKmG9aRn9YYmFQMO3y0mbvVqwJ+uDv+OlvTmd4v3Fpywpf+B1b3UdObS2pIR8qw=='

KEY_SIZE = 256
MIX_SIZE = 12


def create_key():
    random.seed(KEY_SIZE)
    key = random.getrandbits(KEY_SIZE)
    for i in range(MIX_SIZE):
        random.seed(time.time())
        key ^= random.getrandbits(KEY_SIZE // MIX_SIZE)
    key = unhexlify(hex(key)[2:])
    return key


def decrypt(ciphertext, k1, k2):
    ct = b64decode(ciphertext)
    cipher2 = AES.new(k2, AES.MODE_ECB)
    ct = unpad(cipher2.decrypt(ct), AES.block_size)
    cipher1 = AES.new(k1, AES.MODE_ECB)
    plaintext = unpad(cipher1.decrypt(ct), AES.block_size)
    return plaintext


encrypt_outputs = {}
decrypt_outputs = {}

for later_part in tqdm.tqdm(range(2**(KEY_SIZE // MIX_SIZE))):
    random.seed(KEY_SIZE)
    key = random.getrandbits(KEY_SIZE)
    key ^= later_part
    key = unhexlify(hex(key)[2:])
    cipher1 = AES.new(key, AES.MODE_ECB)
    cipher2 = AES.new(key, AES.MODE_ECB)
    ct, pt = None, None
    try:
        pt = unpad(cipher1.decrypt(b64decode(encrypted_public_message)),
                   AES.block_size)
    except Exception:
        pass
    try:
        ct = cipher2.encrypt(pad(public_message, AES.block_size))
    except Exception:
        pass
    if ct is not None:
        encrypt_outputs[key] = ct
    if pt is not None:
        decrypt_outputs[pt] = key

for k1 in encrypt_outputs:
    if encrypt_outputs[k1] in decrypt_outputs:
        k2 = decrypt_outputs[encrypt_outputs[k1]]
        print(f"[*] k1 = {k1}, k2 = {k2}")
        print(decrypt(flag, k1, k2))
        break
