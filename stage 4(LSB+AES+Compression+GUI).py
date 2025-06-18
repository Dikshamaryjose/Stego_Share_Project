import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import zlib
import cv2
import numpy as np

# === Helper functions ===

def compress_encrypt(message):
    compressed = zlib.compress(message.encode())
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(compressed)
    return ciphertext, key, cipher.nonce, tag

def decrypt_decompress(ciphertext, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    original = zlib.decompress(decrypted).decode()
    return original

def message_to_bits(message_bytes):
    return ''.join(format(byte, '08b') for byte in message_bytes)

def bits_to_bytes(bits):
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def hide_lsb_rgb(img_path, message_bits, output_path):
    img = cv2.imread(img_path)
    flat = img.reshape(-1)
    if len(message_bits) > flat.size:
        raise ValueError("Message too long for the selected image.")
    for i in range(len(message_bits)):
        flat[i] = (flat[i] & 0xFE) | int(message_bits[i])
    stego_img = flat.reshape(img.shape)
    cv2.imwrite(output_path, stego_img)

def extract_lsb_rgb(img_path, num_bits):
    img = cv2.imread(img_path)
    flat = img.reshape(-1)
    bits = [str(flat[i] & 1) for i in range(num_bits)]
    return bits_to_bytes(''.join(bits))

# === GUI Application ===

class StegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Image Steganography App")
        self.geometry("600x400")

        self.key = None
        self.nonce = None
        self.tag = None
        self.cipher_len = 0

        # Tabs for encode / decode
        self.tabs = tk.Frame(self)
        self.tabs.pack(pady=10)

        self.encode_btn = tk.Button(self.tabs, text="Encode Message", command=self.encode_screen)
        self.encode_btn.grid(row=0, column=0, padx=10)

        self.decode_btn = tk.Button(self.tabs, text="Decode Message", command=self.decode_screen)
        self.decode_btn.grid(row=0, column=1, padx=10)

        self.frame = None
        self.encode_screen()  # start on encode screen

    def clear_frame(self):
        if self.frame:
            self.frame.destroy()

    def encode_screen(self):
        self.clear_frame()
        self.frame = tk.Frame(self)
        self.frame.pack(fill="both", expand=True)

        tk.Label(self.frame, text="Select Cover Image:").pack()
        self.cover_path_var = tk.StringVar()
        tk.Entry(self.frame, textvariable=self.cover_path_var, width=50).pack()
        tk.Button(self.frame, text="Browse", command=self.browse_cover).pack(pady=5)

        tk.Label(self.frame, text="Enter Secret Message:").pack()
        self.message_entry = tk.Text(self.frame, height=5, width=50)
        self.message_entry.pack()

        tk.Button(self.frame, text="Encode & Save Stego Image", command=self.encode_message).pack(pady=10)

    def browse_cover(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.cover_path_var.set(file_path)

    def encode_message(self):
        img_path = self.cover_path_var.get()
        message = self.message_entry.get("1.0", tk.END).strip()
        if not img_path or not message:
            messagebox.showerror("Error", "Please select an image and enter a message.")
            return
        try:
            ciphertext, key, nonce, tag = compress_encrypt(message)
            self.key, self.nonce, self.tag = key, nonce, tag
            self.cipher_len = len(ciphertext)

            bits = message_to_bits(ciphertext)

            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")])
            if not output_path:
                return

            hide_lsb_rgb(img_path, bits, output_path)

            # Save metadata file
            metadata_path = output_path.rsplit(".",1)[0] + "_metadata.txt"
            with open(metadata_path, "w") as f:
                f.write(base64.b64encode(key).decode() + "\n")
                f.write(base64.b64encode(nonce).decode() + "\n")
                f.write(base64.b64encode(tag).decode() + "\n")
                f.write(str(self.cipher_len) + "\n")

            messagebox.showinfo("Success", f"Message encoded and saved.\nStego image: {output_path}\nMetadata: {metadata_path}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_screen(self):
        self.clear_frame()
        self.frame = tk.Frame(self)
        self.frame.pack(fill="both", expand=True)

        tk.Label(self.frame, text="Select Stego Image:").pack()
        self.stego_path_var = tk.StringVar()
        tk.Entry(self.frame, textvariable=self.stego_path_var, width=50).pack()
        tk.Button(self.frame, text="Browse", command=self.browse_stego).pack(pady=5)

        tk.Label(self.frame, text="Select Metadata File:").pack()
        self.metadata_path_var = tk.StringVar()
        tk.Entry(self.frame, textvariable=self.metadata_path_var, width=50).pack()
        tk.Button(self.frame, text="Browse Metadata", command=self.browse_metadata).pack(pady=5)

        tk.Button(self.frame, text="Decode Message", command=self.decode_message).pack(pady=10)

        self.output_text = tk.Text(self.frame, height=5, width=50)
        self.output_text.pack()

    def browse_stego(self):
        path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if path:
            self.stego_path_var.set(path)

    def browse_metadata(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            self.metadata_path_var.set(path)

    def decode_message(self):
        stego_path = self.stego_path_var.get()
        metadata_path = self.metadata_path_var.get()
        if not stego_path or not metadata_path:
            messagebox.showerror("Error", "Please select both stego image and metadata file.")
            return
        try:
            with open(metadata_path, "r") as f:
                key = base64.b64decode(f.readline().strip())
                nonce = base64.b64decode(f.readline().strip())
                tag = base64.b64decode(f.readline().strip())
                cipher_len = int(f.readline().strip())

            cipher_bytes = extract_lsb_rgb(stego_path, cipher_len * 8)
            message = decrypt_decompress(cipher_bytes, key, nonce, tag)

            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decode message: {e}")

if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()
