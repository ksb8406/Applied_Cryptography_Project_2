#Alice's Program
import os

def encrypt_one_time_pad(message, key):
    # Ensure the message and key are of equal length
    #if len(message) != len(key):
     #   raise ValueError("Message and key must be of equal length")

    # Converts the message and the key to bytes
    message_in_bytes = message.encode()
    key_in_bytes = key

    # Perform bitwise XOR operation
    ciphertext_in_bytes = bytes([message_in_byte ^ key_in_byte for message_in_byte, key_in_byte in zip(message_in_bytes, key_in_bytes)])

    # Converts the ciphertext into hexadecimal
    ciphertext_in_hexadecimal = ciphertext_in_bytes.hex()

    #Takes the ciphertext input and writes them to the file
    with open("ciphertext.txt", "w") as f:
        f.write(ciphertext_in_hexadecimal)
    with open("key.txt", "w") as f:
        f.write(key.hex())

    print("Ciphertext:", ciphertext_in_hexadecimal)
    print("Key:", key.hex())

# Prompt the user for a message
input_message = input("Enter the message: ")

#Generate a random key of the same length as the message
if True:
    random_key = os.urandom(len(input_message))
if True:
    #Encrypts the message using one-time pad 
    encrypt_one_time_pad(input_message, random_key)


#Bob's Program
def decrypt(ciphertext_hex, key_hex):
    # Converts the ciphertext from hexadecimal to bytes
    ciphertext_in_bytes = bytes.fromhex(ciphertext_hex)

    # Convert key from hexadecimal to bytes
    key_in_bytes = bytes.fromhex(key_hex)

    # Perform bitwise XOR operation
    plaintext_in_bytes = bytes([ciphertext_in_byte ^ key_in_byte for ciphertext_in_byte, key_in_byte in zip(ciphertext_in_bytes, key_in_bytes)])

    # Decode plaintext bytes to string
    plaintext = plaintext_in_bytes.decode()

    return plaintext

# Read ciphertext and key from files
with open("ciphertext.txt", "r") as f:
    ciphertext_hexadecimal = f.read().strip()
with open("key.txt", "r") as f:
    key_hex = f.read().strip()

plaintext = decrypt(ciphertext_hexadecimal, key_hex)
print("Decrypted plaintext:", plaintext)
