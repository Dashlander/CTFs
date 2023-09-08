import json
from datetime import datetime
import random
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b"<REDACTED>"

good_seed = datetime.now().strftime("%d/%m/%Y %H:%M")
random.seed(good_seed)


def get_random_bytes(size):
    random_str = bytes([random.randint(0, 255) for _ in range(size)])
    return random_str


key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(flag, AES.block_size))
nonce = b64encode(cipher.iv).decode("utf-8")
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'iv': nonce, 'ciphertext': ct})
print(result)

# Output

# {"iv": "jL5WUu+f9Cfp8lBPiL9Cqw==", "ciphertext": "SMJmHm0WrMqpIIsBimPzKNkmVqJYmfTMWSl67Hlw6cdGFyXQcL/7y9Y23ENomDal"}
