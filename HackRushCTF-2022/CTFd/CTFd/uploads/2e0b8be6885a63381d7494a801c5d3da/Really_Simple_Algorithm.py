from binascii import hexlify
from secret import p, q  # You don't know this


def encrypt(n, e, plaintext):
    m = int(hexlify(plaintext), 16)
    return pow(m, e, n)


flag = b"<REDACTED>"  # You have to find this
n = p * q
e = 65537

print("[*] n: ", n)
print("[*] e: ", e)
ciphertext = encrypt(n, e, flag)
print("[*] c: ", ciphertext)

# Output:
# [*] n:  227010481295437363334259960947493668895875336466084780038173258247009162675779735389791151574049166747880487470296548479
# [*] e:  65537
# [*] c:  103041042558067679617617907514217238456749845848888410352361736997390105286660564458561436949519697513397681148539956095
