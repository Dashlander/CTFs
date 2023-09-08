from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

FLAG = b"<REDACTED>"

key = get_random_bytes(16)


def welcome():
    print("=" * 100, flush=True)
    print("Welcome to the Secret Vault!!!", flush=True)
    print(
        "Here we use military grade encryption to secure the items from attackers.",
        flush=True)
    print("It is said to be even safer than Gringotts :P", flush=True)
    print(
        "We make sure to append our secret to your items so that no one can guess your item",
        flush=True)


BLOCK_SIZE = 16


def pad(ciphertext):
    ciphertext = ciphertext + b'\x00' * (
        (BLOCK_SIZE - len(ciphertext) % BLOCK_SIZE) % BLOCK_SIZE)
    return ciphertext


def secure_encrypt(item):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = item + FLAG
    result = cipher.encrypt(pad(ciphertext))
    return result


def menu():
    print("\n[*] Menu:", flush=True)
    print("1. Encrypt your item", flush=True)
    print("2. Exit", flush=True)
    choice = input("\n[<] Please choose: ")
    return choice


def encrypt_item():
    your_item = input("[<] Please give your item: ").encode()
    result = secure_encrypt(your_item)
    print("[>] Your secured output: ", result, flush=True)


def handle_choice(choice):
    if choice not in ["1", "2"]:
        return
    if choice == "1":
        encrypt_item()
    elif choice == "2":
        exit(0)


def main():
    welcome()
    while True:
        choice = menu()
        handle_choice(choice)


if __name__ == "__main__":
    main()
