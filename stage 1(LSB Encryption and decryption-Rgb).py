import cv2
import numpy as np

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
if __name__ == "__main__":
    # Test paths
    input_image = "test_input.png"       # <- Make sure this image exists!
    output_image = "test_output.png"
    secret = "Hello from Stego Share!"

    # Encode
    encode_lsb(input_image, secret, output_image)

    # Decode
    decoded = decode_lsb(output_image)
    print("[DECODED MESSAGE]:", decoded)
