import argparse
import argon2
import binascii
from getpass import getpass
import os
import struct
import time
from Crypto.Cipher import AES

def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", type=str, help="path to input file")
    args = parser.parse_args()

    print("please enter the password: ")
    password = getpass()

    # Read the encrypted file
    with open(f"{args.input_file}", "rb") as f:
        int_step = 8
        int_num = 3
        step = 16

        argon_config = f.read(int_step * int_num) # read 24 bytes for argon2id config
        time_cost, memory_cost, parallelism = struct.unpack('qqq', argon_config)

        argon_salt = f.read(step)
        file_encryption_key_encrypted = f.read(2*step)
        fek_nonce = f.read(step)
        fek_tag = f.read(step)
        data_enc_nonce = f.read(step)
        data_enc_tag = f.read(step)
        encrypted_data = f.read()

    time_argon_start = time.time()
    # generate key encryption key using argon2id
    key_encryption_key = argon2.hash_password_raw(
        time_cost=time_cost, memory_cost=2**memory_cost, parallelism=parallelism, hash_len=32,
        password=password.encode(), salt=argon_salt, type=argon2.low_level.Type.ID)
    time_argon_end = time.time()
    argon_total_time = time_argon_end - time_argon_start
    print("Total time taken: {:.2f} seconds".format(argon_total_time))

    # use key encryption key to decrypt file encryption key
    file_encryption_key = decrypt_AES_GCM(
        (file_encryption_key_encrypted, fek_nonce, fek_tag),
        key_encryption_key)

    # decrypt file
    decrypted_data = decrypt_AES_GCM(
        (encrypted_data, data_enc_nonce, data_enc_tag),
        file_encryption_key
    )

    # write the decrypted file to output
    output_file = f"dec_{args.input_file}".replace(".enc", "")
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    main()

