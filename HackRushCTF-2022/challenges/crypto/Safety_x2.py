import random
import time
from binascii import unhexlify
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

KEY_SIZE = 256  # Good luck brute forcing this :)
MIX_SIZE = 12


def create_key():
    random.seed(KEY_SIZE)
    key = random.getrandbits(KEY_SIZE)
    for i in range(MIX_SIZE):
        random.seed(time.time())
        key ^= random.getrandbits(KEY_SIZE // MIX_SIZE)
    key = unhexlify(hex(key)[2:])
    return key


def encrypt(plaintext, k1, k2):
    cipher1 = AES.new(k1, AES.MODE_ECB)
    ct = cipher1.encrypt(pad(plaintext, AES.block_size))
    cipher2 = AES.new(k2, AES.MODE_ECB)  # Double protection
    ct = cipher2.encrypt(pad(ct, AES.block_size))
    ciphertext = b64encode(ct)
    return ciphertext


k1 = create_key()
k2 = create_key()

public_message = b"I am about to send something very secret. Please pay close attention"
secret_message = b"Flag: <REDACTED>"

print("[*] Public message: ", public_message)
print("[*] encrypted public_message: ", encrypt(public_message, k1, k2))
print("[*] encrypted secret message: ", encrypt(secret_message, k1, k2))

# Output:
# [*] Public message:  b'I am about to send something very secret. Please pay close attention'
# [*] encrypted public_message:  b'CzNUxzyzGWHsoFvp49gYrlucE1gX5IxiouF5siJjSpASDM5GSil9oYYa/5Z8scfK8P3HW8reCykJVw58E8OSbjAb59IpYApxjOQbGk8sa6anLCl/4HVvdR05tLakhHyr'
# [*] encrypted secret message:  b'IUShVotCVlgw2xPXa1glLdrXKmG9aRn9YYmFQMO3y0mbvVqwJ+uDv+OlvTmd4v3Fpywpf+B1b3UdObS2pIR8qw=='

