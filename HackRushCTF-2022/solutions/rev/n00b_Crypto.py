map = {0: 3, 1: 5, 2: 1, 3: 0, 4: 2, 5: 6, 6: 4, 7: 7}
invmap = {3: 0, 5: 1, 1: 2, 0: 3, 2: 4, 6: 5, 4: 6, 7: 7}


def mixup(val):
    new_val = 0
    for i in range(8):
        new_val |= (val & 1) << map[i]
        val = val >> 1
    return new_val


def unmix(val):
    new_val = 0
    for i in range(8):
        new_val |= (val & 1) << invmap[i]
        val = val >> 1
    return new_val


def encrypt(plaintext):
    ciphertext = ""
    for a in plaintext:
        val = ord(a)
        new_val = mixup(val)
        ciphertext += chr(new_val)
    return ciphertext


def decrypt(ciphertext):
    plaintext = ""
    for a in ciphertext:
        val = ord(a)
        new_val = unmix(val)
        plaintext += chr(new_val)
    return plaintext

enc = "\x11Xxy4^|Q8\x16""2}\x1d{^?NQD\x1eLRsn?\x19[TSl\x1bls\x16?8t]TV{_"
print(decrypt(enc))
