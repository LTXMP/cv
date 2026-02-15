import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# MUST MATCH C++ CLIENT KEYS
# MUST MATCH C++ CLIENT KEYS
KEY = b'9sX2kL5mN8pQ1rT4vW7xZ0yA3bC6dE9f' 
IV = b'H1j2K3m4N5p6Q7r8' 

def encrypt_file(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    with open(input_file, 'rb') as f:
        data = f.read()

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"Encrypted {input_file} -> {output_file}")

if __name__ == "__main__":
    encrypt_file("best.onnx", "best.enc")
