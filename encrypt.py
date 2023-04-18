import argparse
import argon2
import binascii
from getpass import getpass
import os
import struct
import time
from Crypto.Cipher import AES

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", type=str, help="path to input file")
    parser.add_argument("--time_cost", type=int, default=1000, help="argoni2d parameter time cost")
    parser.add_argument("--memory_cost", type=int, default=15, help="argon2id parameter memory cost, if 15, then the memory cost is 2**15")
    parser.add_argument("--parallelism", type=int, default=2, help="argon2id parameter parallelism")
    args = parser.parse_args()

    print("please enter the password: ")
    password = getpass()

    print("please enter the password again: ")
    password2 = getpass()

    assert(password == password2)

    # Read the input file
    with open(args.input_file, "rb") as f:
        input_data = f.read()
    
    # generate key encryption key using argon2id
    argon_salt = os.urandom(16)

    time_argon_start = time.time()
    key_encryption_key = argon2.hash_password_raw(
        time_cost=args.time_cost,
        memory_cost=2**args.memory_cost,
        parallelism=args.parallelism,
        hash_len=32,
        password=password.encode(),
        salt=argon_salt,
        type=argon2.low_level.Type.ID
    )
    time_argon_end = time.time()
    argon_total_time = time_argon_end - time_argon_start
    print("Total time taken: {:.2f} seconds".format(argon_total_time))

    # generate file encryption key 
    file_encryption_key = os.urandom(32)

    # protect the file encryption key using the key encryption key
    file_encryption_key_encrypted, fek_nonce, fek_tag = encrypt_AES_GCM(file_encryption_key, key_encryption_key)

    # encrypt the file using file encryption key
    encrypted_data, data_enc_nonce, data_enc_tag = encrypt_AES_GCM(input_data, file_encryption_key)

    # write the argon params, encrypted file encryption key, and encrypted data together
    with open(f"{args.input_file}.enc", "wb") as f:
        argon_config = struct.pack("qqq", args.time_cost, args.memory_cost, args.parallelism)
        f.write(argon_config) # 3 * 8 bytes
        f.write(argon_salt) # 16 bytes
        f.write(file_encryption_key_encrypted) # 32 bytes
        f.write(fek_nonce) # 16 bytes
        f.write(fek_tag) # 16 bytes
        f.write(data_enc_nonce) # 16 bytes
        f.write(data_enc_tag) # 16 bytes
        f.write(encrypted_data)

if __name__ == "__main__":
    main()


