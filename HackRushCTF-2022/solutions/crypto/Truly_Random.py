import random
from base64 import b64decode
from datetime import timedelta, datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

given = {
    "iv":
    "jL5WUu+f9Cfp8lBPiL9Cqw==",
    "ciphertext":
    "SMJmHm0WrMqpIIsBimPzKNkmVqJYmfTMWSl67Hlw6cdGFyXQcL/7y9Y23ENomDal"
}


def get_random_bytes(size):
    random_str = bytes([random.randint(0, 255) for _ in range(size)])
    return random_str


# curr_time = datetime.now()
curr_time = datetime(2022, 3, 30, 20, 25)

while True:
    try:
        good_seed = curr_time.strftime("%d/%m/%Y %H:%M")
        random.seed(good_seed)

        key = get_random_bytes(16)

        iv = b64decode(given['iv'])
        ct = b64decode(given['ciphertext'])

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)

        if b"HackRushCTF" in pt:
            print("FLAG: ", pt)
            break
    except Exception as e:
        pass
    curr_time = curr_time - timedelta(minutes=1)
