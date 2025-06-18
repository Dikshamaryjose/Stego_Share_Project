import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import zlib

def to_bin(data):
    if isinstance(data, str):
        return ''.join(format(ord(i), '08b') for i in data)
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [format(i, '08b') for i in data]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, '08b')
    else:
        raise TypeError("Unsupported type")

def encode_lsb(image_path, secret_message, output_path):
    image = cv2.imread(image_path)
    n_bytes = image.shape[0] * image.shape[1] * 3 // 8
    secret_message += '####'
    data_index = 0
    binary_secret = to_bin(secret_message)

    for row in image:
        for pixel in row:
            for channel in range(3):
                if data_index < len(binary_secret):
                    pixel[channel] = int(to_bin(pixel[channel])[:-1] + binary_secret[data_index], 2)
                    data_index += 1

    cv2.imwrite(output_path, image)
    print(f"[INFO] Message encoded into {output_path}")

def encrypt_message(message, key):
    key = key.ljust(16)[:16].encode()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return iv + ct

def compress_message(message):
    return zlib.compress(message.encode())

def decode_lsb(image_path):
    image = cv2.imread(image_path)
    binary_data = ""

    for row in image:
        for pixel in row:
            for channel in range(3):
                binary_data += to_bin(pixel[channel])[-1]

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_message = ""
    for byte in all_bytes:
        char = chr(int(byte, 2))
        decoded_message += char
        if decoded_message[-4:] == '####':
            break
    return decoded_message[:-4]

def decrypt_message(encrypted_message, key):
    key = key.ljust(16)[:16].encode()
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

def decompress_message(compressed):
    return zlib.decompress(compressed).decode()

if __name__ == "__main__":
    input_image = "test_input.png"
    output_image = "test_output.png"
    secret = "Hello from Stego Share!"
    key = "mysecurekey123"  # Can be any 16-char key

    # Encrypt the message
    encrypted = encrypt_message(secret, key)
    print("[ENCRYPTED]:", encrypted)

    # Encode the encrypted message
    encode_lsb(input_image, encrypted, output_image)

    # Decode the message back from the image
    decoded_encrypted = decode_lsb(output_image)
    print("[DECODED ENCRYPTED]:", decoded_encrypted)

    # Decrypt the decoded message
    decrypted = decrypt_message(decoded_encrypted, key)
    print("[FINAL DECRYPTED MESSAGE]:", decrypted)
