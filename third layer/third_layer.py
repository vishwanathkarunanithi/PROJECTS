import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import cv2
import numpy as np
import threading
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt

# ---------- Constants ----------
AES_KEY_SIZE = 32
SALT = b'my_static_salt_for_stego'
HEADER_LEN_BITS = 64   # 32 bits for Hamming-encoded message length, 32 bits for aes byte length
REDUNDANCY_FACTOR = 3

# ---------- Hamming(7,4) Code ----------
def hamming74_encode(data_bits):
    # ensure exactly 4 bits (pad with zeros if needed)
    if len(data_bits) < 4:
        data_bits = data_bits.ljust(4, '0')
    d1, d2, d3, d4 = map(int, data_bits)
    p1 = (d1 + d2 + d4) % 2
    p2 = (d1 + d3 + d4) % 2
    p3 = (d2 + d3 + d4) % 2
    return f"{p1}{p2}{d1}{p3}{d2}{d3}{d4}"

def hamming74_decode(bits):
    # bits: length 7
    bits = list(map(int, bits))
    p1, p2, d1, p3, d2, d3, d4 = bits
    s1 = (p1 + d1 + d2 + d4) % 2
    s2 = (p2 + d1 + d3 + d4) % 2
    s3 = (p3 + d2 + d3 + d4) % 2
    pos = s1 * 1 + s2 * 2 + s3 * 4
    if pos != 0:
        bits[pos - 1] ^= 1  # correct the bit
    # return the 4 data bits as string
    return f"{bits[2]}{bits[4]}{bits[5]}{bits[6]}"

# ---------- AES Cryptography ----------
def get_key_from_password(password):
    return scrypt(password.encode('utf-8'), salt=SALT, key_len=AES_KEY_SIZE, N=2**14, r=8, p=1)

def aes_encrypt(text, password):
    key = get_key_from_password(password)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(data, password):
    key = get_key_from_password(password)
    if len(data) < 16 + AES.block_size:
        raise ValueError("Ciphertext too short for AES CBC decryption.")
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')

# ---------- Utilities and PN Sequence ----------
def bits_from_bytes(data):
    return ''.join(f'{b:08b}' for b in data)

def bytes_from_bits(bits):
    if len(bits) % 8 != 0:
        raise ValueError("bits length must be a multiple of 8 to convert to bytes.")
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def generate_pn_seed(password):
    # use a larger portion of SHA256 hex to reduce collisions
    full_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # take 16 hex chars -> 64-bit integer
    return int(full_hash[:16], 16)

def generate_pn(seq_len, seed):
    rng = np.random.default_rng(seed)
    return rng.choice([-1, 1], size=seq_len)

# ---------- Steganography Engine ----------
def embed_block(block, bit, pn_seed, alpha):
    # embed into blue channel using block DCT
    blue = block[:, :, 0].astype(np.float32)
    bs = block.shape[0] * block.shape[1]
    pn = generate_pn(bs, pn_seed).reshape(block.shape[0], block.shape[1])
    sig = 1 if int(bit) else -1
    d = cv2.dct(blue)
    d += alpha * sig * pn
    idct = cv2.idct(d)
    block[:, :, 0] = np.uint8(np.clip(idct, 0, 255))

def extract_block(block, pn_seed):
    blue = block[:, :, 0].astype(np.float32)
    bs = block.shape[0] * block.shape[1]
    pn = generate_pn(bs, pn_seed).reshape(block.shape[0], block.shape[1])
    d = cv2.dct(blue)
    s = np.sum(d * pn)
    return '1' if s >= 0 else '0'

# ---------- Redundancy Functions ----------
def apply_redundancy(bit_stream, factor=REDUNDANCY_FACTOR):
    return ''.join(bit * factor for bit in bit_stream)

def majority_vote_decode(redundant_bits, factor=REDUNDANCY_FACTOR):
    if len(redundant_bits) % factor != 0:
        raise ValueError(f"Redundant bit stream length must be a multiple of {factor}.")
    decoded_bits = ''
    for i in range(0, len(redundant_bits), factor):
        chunk = redundant_bits[i:i+factor]
        decoded_bits += '1' if chunk.count('1') > chunk.count('0') else '0'
    return decoded_bits

# ---------- Main Logic and Sanity Check ----------
def do_encode():
    try:
        infile = entry_input.get().strip()
        outfile = entry_output.get().strip()
        secret = txt_secret.get("1.0", tk.END).strip()
        password = entry_password.get()
        bs = int(entry_block_size.get())
        alpha = float(entry_alpha.get())
        if not all([infile, outfile, secret, password]):
            raise ValueError("All fields must be filled.")
        img = cv2.imread(infile)
        if img is None:
            raise ValueError(f"Cannot read image: {infile}")
        h, w = img.shape[:2]
        blocks = [(r, c) for r in range(0, h, bs) for c in range(0, w, bs) if r + bs <= h and c + bs <= w]
        if not blocks:
            raise ValueError("No blocks available for embedding with the current block size.")
        aes_bytes = aes_encrypt(secret, password)
        byte_bits = bits_from_bytes(aes_bytes)

        # ensure bitstream is multiple of 4 for Hamming(7,4)
        pad_bits = (4 - (len(byte_bits) % 4)) % 4
        if pad_bits:
            byte_bits += '0' * pad_bits
        safe_log(f"Padded {pad_bits} bits to make length multiple of 4 for Hamming encoding.")

        # Hamming encode (4 -> 7)
        hamming_encoded_bits = ''.join(hamming74_encode(byte_bits[i:i+4]) for i in range(0, len(byte_bits), 4))
        msg_len = len(hamming_encoded_bits)
        aes_len = len(aes_bytes)

        # Header: 32 bits for msg_len, 32 bits for aes_len (bytes)
        header_bits = bin(msg_len)[2:].zfill(32) + bin(aes_len)[2:].zfill(32)
        if len(header_bits) != HEADER_LEN_BITS:
            raise ValueError("Header bits size mismatch.")
        protected_header = apply_redundancy(header_bits)
        protected_message = apply_redundancy(hamming_encoded_bits)
        full_bits_to_embed = protected_header + protected_message

        if len(full_bits_to_embed) > len(blocks):
            raise ValueError(f"Message too long. Required: {len(full_bits_to_embed)}, Available: {len(blocks)}")

        pn_seed = generate_pn_seed(password)
        safe_log(f"Embedding {len(full_bits_to_embed)} bits into image (Hamming msg bits: {msg_len}, AES bytes: {aes_len})...")
        for i, bit in enumerate(full_bits_to_embed):
            r, c = blocks[i]
            embed_block(img[r:r+bs, c:c+bs], bit, pn_seed, alpha)
            if i % 100 == 0:
                safe_progress(int((i + 1) / len(full_bits_to_embed) * 100))
        if not outfile.lower().endswith('.png'):
            outfile += '.png'
            safe_log("Warning: Output automatically saved as PNG for lossless quality.")
        cv2.imwrite(outfile, img)
        safe_log(f"✅ Encoding Done. Saved to {outfile}")
        safe_progress(100)
    except Exception as e:
        safe_log(f"❌ Encode error: {e}")
        messagebox.showerror("Encoding Error", f"An error occurred:\n{e}")
        safe_progress(0)

def do_decode():
    try:
        infile = entry_input.get().strip()
        password = entry_password.get()
        bs = int(entry_block_size.get())
        if not all([infile, password]):
            raise ValueError("Input image and password are required.")
        img = cv2.imread(infile)
        if img is None:
            raise ValueError(f"Cannot read image: {infile}")
        h, w = img.shape[:2]
        blocks = [(r, c) for r in range(0, h, bs) for c in range(0, w, bs) if r + bs <= h and c + bs <= w]
        if not blocks:
            raise ValueError("No blocks available for extraction with the current block size.")
        pn_seed = generate_pn_seed(password)
        header_redundant_len = HEADER_LEN_BITS * REDUNDANCY_FACTOR
        if len(blocks) < header_redundant_len:
            raise ValueError("Image too small to contain a header.")
        safe_log("Extracting header...")
        header_redundant_bits = ''.join(extract_block(img[r:r+bs, c:c+bs], pn_seed) for r, c in blocks[:header_redundant_len])
        safe_log(f"Raw extracted header bits (first 64): {header_redundant_bits[:64]}")
        header_bits = majority_vote_decode(header_redundant_bits)
        safe_log(f"Header bits after majority vote: {header_bits}")
        if len(header_bits) != HEADER_LEN_BITS:
            raise ValueError("Invalid header length after majority vote.")

        # parse header: first 32 bits => msg_len (Hamming-encoded bits), next 32 bits => aes_len (bytes)
        msg_len = int(header_bits[:32], 2)
        aes_len = int(header_bits[32:], 2)
        msg_redundant_len = msg_len * REDUNDANCY_FACTOR
        total_len = header_redundant_len + msg_redundant_len
        if msg_len == 0 or total_len > len(blocks):
            raise ValueError(f"Invalid message length ({msg_len}) from header. This almost always means:\n\n1. The Password is wrong.\n2. The Block Size is wrong.\n3. You are decoding the original image, not the encoded one.")
        safe_log(f"Header decoded. Expecting message of {msg_len} bits (Hamming-encoded). AES payload bytes expected: {aes_len}")

        message_blocks = blocks[header_redundant_len:total_len]
        redundant_extracted_bits = ''
        for i, (r, c) in enumerate(message_blocks):
            redundant_extracted_bits += extract_block(img[r:r+bs, c:c+bs], pn_seed)
            if i % 100 == 0:
                safe_progress(int((i + 1) / len(message_blocks) * 100))
        hamming_extracted_bits = majority_vote_decode(redundant_extracted_bits)
        if len(hamming_extracted_bits) != msg_len:
            raise ValueError("Length mismatch after majority vote.")
        if len(hamming_extracted_bits) % 7 != 0:
            raise ValueError("Hamming-encoded bits length not a multiple of 7.")
        decoded_byte_bits = ''.join(hamming74_decode(hamming_extracted_bits[i:i+7]) for i in range(0, len(hamming_extracted_bits), 7))
        # decoded_byte_bits length should be a multiple of 8
        if len(decoded_byte_bits) % 8 != 0:
            raise ValueError("Decoded bitstream length not a multiple of 8 after Hamming decode.")
        aes_bytes = bytes_from_bits(decoded_byte_bits)
        if len(aes_bytes) < aes_len:
            raise ValueError("Reconstructed AES bytes shorter than expected. Possible decoding error.")
        aes_bytes = aes_bytes[:aes_len]  # trim to original AES payload length
        text = aes_decrypt(aes_bytes, password)
        txt_secret.delete("1.0", tk.END)
        txt_secret.insert("1.0", text)
        safe_log("✅ Decoding Done. Message displayed.")
        root.after(0, lambda: prompt_and_save(text))
        safe_progress(100)
    except Exception as e:
        safe_log(f"❌ Decode error: {e}")
        messagebox.showerror("Decoding Error", f"An error occurred:\n{e}")
        safe_progress(0)

def run_sanity_check():
    try:
        safe_log("\n--- Running Diagnostic Sanity Check ---")
        password = entry_password.get()
        bs = int(entry_block_size.get())
        alpha = float(entry_alpha.get())
        if not password:
            raise ValueError("Password is required for sanity check.")
        pn_seed = generate_pn_seed(password)
        original_block = np.random.randint(0, 256, (bs, bs, 3), dtype=np.uint8)
        block_for_1 = original_block.copy()
        embed_block(block_for_1, '1', pn_seed, alpha)
        extracted_1 = extract_block(block_for_1, pn_seed)
        safe_log(f"Test 1: Embedded '1', Extracted '{extracted_1}'")
        block_for_0 = original_block.copy()
        embed_block(block_for_0, '0', pn_seed, alpha)
        extracted_0 = extract_block(block_for_0, pn_seed)
        safe_log(f"Test 2: Embedded '0', Extracted '{extracted_0}'")
        if extracted_1 == '1' and extracted_0 == '0':
            safe_log("✅ Sanity Check Passed. Core engine is working correctly.")
            messagebox.showinfo("Sanity Check Passed", "The core embed/extract functions are working correctly.\nThe decoding issue is likely due to a wrong password, file, or block size.")
        else:
            safe_log("❌ Sanity Check Failed. There may be an issue with a library (OpenCV/NumPy) or parameter choice.")
            messagebox.showerror("Sanity Check Failed", "The core embed/extract functions failed.\nThis could indicate a problem with your Python environment or libraries.")
    except Exception as e:
        safe_log(f"❌ Sanity Check error: {e}")
        messagebox.showerror("Sanity Check Error", f"An error occurred during the check:\n{e}")

# ---------- GUI Setup and Control Functions ----------
def choose_input():
    f = filedialog.askopenfilename(title="Select Input Image", filetypes=[("Image Files", "*.png;*.bmp;*.tiff")])
    if f:
        entry_input.delete(0, tk.END)
        entry_input.insert(0, f)

def choose_output():
    f = filedialog.asksaveasfilename(title="Save Output Image As", defaultextension=".png", filetypes=[("PNG Image", "*.png")])
    if f:
        entry_output.delete(0, tk.END)
        entry_output.insert(0, f)

def load_secret_file():
    f = filedialog.askopenfilename(title="Load Secret from Text File", filetypes=[("Text Files", "*.txt")])
    if f:
        with open(f, 'r', encoding='utf-8') as file:
            txt_secret.delete("1.0", tk.END)
            txt_secret.insert("1.0", file.read())

def prompt_and_save(text_to_save):
    filepath = filedialog.asksaveasfilename(title="Save Decoded Message", defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if filepath:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(text_to_save)
            safe_log(f"✅ Decoded message saved to {filepath}")
        except Exception as e:
            safe_log(f"❌ Failed to save file: {e}")
            messagebox.showerror("Save Error", f"Could not save file:\n{e}")

def start_encode():
    threading.Thread(target=do_encode, daemon=True).start()

def start_decode():
    threading.Thread(target=do_decode, daemon=True).start()

def start_sanity_check():
    threading.Thread(target=run_sanity_check, daemon=True).start()

def safe_log(message):
    root.after(0, lambda: log_message(message))

def log_message(message):
    txt_log.config(state='normal')
    txt_log.insert(tk.END, message + "\n")
    txt_log.see(tk.END)
    txt_log.config(state='disabled')

def safe_progress(value):
    root.after(0, lambda: progress_var.set(value))

# --- GUI Layout ---
root = tk.Tk()
root.title("Robust Image Steganography Tool")
root.geometry("600x620")
frm = tk.Frame(root, padx=10, pady=10)
frm.pack(fill=tk.BOTH, expand=True)

tk.Label(frm, text="Input Image").grid(row=0, column=0, sticky="w", pady=2)
entry_input = tk.Entry(frm, width=60)
entry_input.grid(row=0, column=1, columnspan=2)
tk.Button(frm, text="Browse...", command=choose_input).grid(row=0, column=3)

tk.Label(frm, text="Output Image").grid(row=1, column=0, sticky="w", pady=2)
entry_output = tk.Entry(frm, width=60)
entry_output.grid(row=1, column=1, columnspan=2)
tk.Button(frm, text="Browse...", command=choose_output).grid(row=1, column=3)

tk.Label(frm, text="Secret Message").grid(row=2, column=0, sticky="nw", pady=2)
txt_secret = tk.Text(frm, width=50, height=6)
txt_secret.grid(row=2, column=1, columnspan=2, sticky="ew")
tk.Button(frm, text="Load File...", command=load_secret_file).grid(row=2, column=3, sticky="n")

tk.Label(frm, text="Password").grid(row=3, column=0, sticky="w", pady=5)
entry_password = tk.Entry(frm, width=30, show="*")
entry_password.grid(row=3, column=1)

param_frame = tk.Frame(frm)
param_frame.grid(row=4, column=1, columnspan=3, sticky="w", pady=5)
tk.Label(param_frame, text="Block Size:").pack(side=tk.LEFT, padx=(0, 5))
entry_block_size = tk.Entry(param_frame, width=5)
entry_block_size.insert(0, "8")
entry_block_size.pack(side=tk.LEFT)
tk.Label(param_frame, text="Alpha:").pack(side=tk.LEFT, padx=(15, 5))
entry_alpha = tk.Entry(param_frame, width=7)
entry_alpha.insert(0, "50.0")  # large for testing; reduce for less visible distortion
entry_alpha.pack(side=tk.LEFT)

btn_frame = tk.Frame(frm)
btn_frame.grid(row=5, column=0, columnspan=4, pady=10)
tk.Button(btn_frame, text="Encode Message", command=start_encode, width=16, height=2, bg="#d0e0d0").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Decode Message", command=start_decode, width=16, height=2, bg="#d0d0e0").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Run Sanity Check", command=start_sanity_check, width=16, height=2, bg="#f0e0d0").pack(side=tk.LEFT, padx=5)

tk.Label(frm, text="Log").grid(row=6, column=0, sticky="w", pady=(10, 0))
txt_log = scrolledtext.ScrolledText(frm, width=80, height=12, state='disabled', wrap=tk.WORD)
txt_log.grid(row=7, column=0, columnspan=4, sticky="ew")
progress_var = tk.DoubleVar()
ttk.Progressbar(frm, length=520, mode='determinate', variable=progress_var).grid(row=8, column=0, columnspan=4, pady=10)
frm.columnconfigure(1, weight=1)

root.mainloop()
