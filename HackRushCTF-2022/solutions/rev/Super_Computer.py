p = 8310290075942797583


def efficient_large_value(init):
    if init <= 3:
        return init
    value_map = {0: 0, 1: 1, 2: 2, 3: 3}
    for val in range(4, init + 1):
        ans = ((value_map[val - 2] + 2) ^ ((value_map[val - 1] + 1) +
                                           (value_map[val - 3] + 3))) % p
        value_map[val] = ans
    return value_map[init]


def encrypt(key, data):
    encrypted = []
    for c in data:
        val = ord(c)
        enc = key
        for i in range(0, 64, 8):
            enc = enc ^ (((val >> i // 8) & 1) << i)
        key += 0x1337
        encrypted.append(enc)
    return encrypted


def decrypt(k, enc):
    decrypted = ''
    for i in enc:
        dec = 0
        b = i ^ k
        for j in range(0, 64, 8):
            dec |= ((b & 1) << j // 8)
            b = b >> 8
        dec = chr(dec)
        k += 0x1337
        decrypted += dec
    return decrypted


k = efficient_large_value(0xf00de)
enc = [6727001931715929522, 6727003031210785000, 6727003031210790177, 6727003031227571798, 6727001927404204942, 6727003026915771844, 6727003026915842557, 6727003031227591731, 6727001931699191403, 6727001927404294817, 6727001931699266776, 6727003026932643854, 6727001931699277127, 6727001931699281789, 6727001931699221428, 6727001927421101290, 6727001931716008227, 6727003026915896664, 6727001927421116049, 6727001927404344263, 6726721551939200255, 6727003026915915829, 6727001927421070445, 6727001927421009570, 6727003026915930842, 6726721551939225105, 6727003026915874889, 6727001931699219582, 6727003026915950262, 6727001931699229677, 6727001927404267045, 6727001931716016475, 6727003026932681875]
print(k)
print(enc)
print(decrypt(k, enc))
