from Crypto.Random import get_random_bytes
from hashlib import sha256

# Port: 34900

secret = get_random_bytes(16)
assert (len(secret) == 16)

FLAG = "HackRushCTF{us3_HM4c_fOR_Si6NATUre_veRiFicATion}"

def welcome():
    print("[*] Welcome to the Hacker's Hut!", flush=True)
    print(
        "[*] This is a recruiting test to see if you can attack secure connections.",
        flush=True)
    print(
        "[*] Since modern internet is getting stronger, you won't know the secrets shared by the two hosts anymore.",
        flush=True)
    print(
        "[*] We give you a chance to modify the traffic between two hosts whose shared secret you don't know"
    )


def sign_message(msg):
    sig = sha256(secret + msg)
    return sig.hexdigest()


def verify_signature(msg, sig):
    return sign_message(msg) == sig


def get_groups(form_data):
    fields = form_data.split(b"&")
    group_data = fields[-1]
    groups = group_data.split(b"=")[1].split(b",")
    return groups


def chal():
    normal_form_data = b"msg=hello how are you?&user=bob&group=users,friend"
    signature = sign_message(normal_form_data)
    print("[+] Here is the data that we got on the network: ",
          normal_form_data)
    print("[+] Here is its signature: ", signature)
    print(
        "You now have to change the message and signature so that the signature is still valid"
    )
    new_msg = bytes.fromhex(input("New message (hex encoded): ").strip())
    new_signature = input("New signature: ").strip()
    if verify_signature(new_msg, new_signature):
        print("Yaay, the signature is verified", flush=True)
        groups = get_groups(new_msg)
        if b"admin" in groups:
            print("[+] Flag is: ", FLAG)
    else:
        print("You have been detected, leave", flush=True)


def main():
    welcome()
    chal()


if __name__ == "__main__":
    main()
