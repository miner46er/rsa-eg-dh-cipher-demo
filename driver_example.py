import iterator, modes, rsa, elgamal, shamaq

# Initialize cipher (yes, it's that modular)
cipher = rsa.RSA()
# cipher = elgamal.Elgamal()
# cipher = shamaq.Shamaq(key)

# Generate private and public key
# No need to generate key for Shamaq
cipher.generate_key()

# Get private and public key for savekeeping
private_key_base64 = cipher.get_private_key_base64()
public_key_base64 = cipher.get_public_key_base64()

# Initialize mode
mode = modes.ECB(cipher)

# Encryption

## Setup the input
### Get the iterator for file
filename = "elgamal.py"
file_iterator = iterator.file_block_iterator(filename, mode.block_size_plaintext)

### Get the iterator for string input
mock_input = "Aku punya kucing unyu banget"
input_bytes = mock_input.encode("latin-1")
input_iterator = iterator.bytes_block_iterator(input_bytes, mode.block_size_plaintext)

## Setup the output
### Output to file
output_filename = "encrypted_elgamal"
with open(output_filename, "wb") as file:
    # This is where the encryption happens
    for data in mode.encrypt(file_iterator):
        file.write(data)

### Output to a string
encrypted_string = ""
# This is where the encryption happens
for data in mode.encrypt(input_iterator):
    encrypted_string += data.decode("latin-1")
print("encrypted string:", encrypted_string)


# Decryption

## Setup the input
### Get the iterator for file
filename = "encrypted_elgamal"
file_iterator = iterator.file_block_iterator(filename, mode.block_size_ciphertext)

### Get the iterator for string input
# We'll use the string from encryption before
input_bytes = encrypted_string.encode("latin-1")
input_iterator = iterator.bytes_block_iterator(input_bytes, mode.block_size_ciphertext)

## Setup the output
### Output to file
output_filename = "decrypted_elgamal"
with open(output_filename, "wb") as file:
    # This is where the encryption happens
    for data in mode.decrypt(file_iterator):
        file.write(data)

### Output to a string
decrypted_string = ""
# This is where the decryption happens
for data in mode.decrypt(input_iterator):
    decrypted_string += data.decode("latin-1")
print("decrypted string:", decrypted_string)
