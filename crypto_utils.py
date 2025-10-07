import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import math

# --- CÁC HÀM HỖ TRỢ ---
def gcd(a, b):
    while b: a, b = b, a % b
    return a

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# --- CÁC THUẬT TOÁN MÃ HÓA CỔ ĐIỂN ---

def caesar_cipher(text, shift, encrypt=True):
    # ... (Giữ nguyên)
    result = ""
    shift_amount = shift if encrypt else -shift
    for char in text:
        if 'a' <= char <= 'z':
            start = ord('a'); result += chr((ord(char) - start + shift_amount) % 26 + start)
        elif 'A' <= char <= 'Z':
            start = ord('A'); result += chr((ord(char) - start + shift_amount) % 26 + start)
        else:
            result += char
    return result

def transposition_cipher(text, key, encrypt=True):
    # ... (Giữ nguyên)
    if encrypt:
        num_cols = len(key)
        num_rows = math.ceil(len(text) / num_cols)
        padded_text = text.ljust(num_rows * num_cols, '_')
        grid = [padded_text[i:i+num_cols] for i in range(0, len(padded_text), num_cols)]
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        ciphertext = "".join(grid[row_idx][col_idx] for col_idx in key_order for row_idx in range(num_rows))
        return ciphertext
    else:
        num_cols, num_rows = len(key), math.ceil(len(text) / num_cols)
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        num_shaded_boxes = (num_cols * num_rows) - len(text)
        grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        text_idx = 0
        for col_idx in key_order:
            for row_idx in range(num_rows):
                if not (row_idx == num_rows - 1 and key_order.index(col_idx) >= num_cols - num_shaded_boxes):
                    if text_idx < len(text):
                        grid[row_idx][col_idx] = text[text_idx]; text_idx += 1
        return "".join("".join(row) for row in grid).rstrip('_')

def affine_cipher(text, key_a, key_b, encrypt=True):
    # ... (Giữ nguyên)
    result = ""
    mod_inv_a = mod_inverse(key_a, 26)
    if mod_inv_a is None and not encrypt: raise ValueError(f"Hệ số a={key_a} không hợp lệ.")
    for char in text:
        if 'a' <= char <= 'z':
            start = ord('a'); x = ord(char) - start
            if encrypt: result += chr(((key_a * x + key_b) % 26) + start)
            else: result += chr(((mod_inv_a * (x - key_b + 26)) % 26) + start)
        elif 'A' <= char <= 'Z':
            start = ord('A'); x = ord(char) - start
            if encrypt: result += chr(((key_a * x + key_b) % 26) + start)
            else: result += chr(((mod_inv_a * (x - key_b + 26)) % 26) + start)
        else: result += char
    return result

# CẢI TIẾN: Sửa lỗi logic và cải thiện thông báo lỗi cho Hill
def hill_cipher(text, key_matrix, encrypt=True):
    # Kiểm tra tính khả nghịch của ma trận NGAY TỪ ĐẦU
    det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) % 26
    if gcd(det, 26) != 1:
        # Đây là thông báo lỗi mới, cụ thể hơn
        raise ValueError("Khóa không hợp lệ (định thức của ma trận là số chẵn hoặc 13).")

    processed_text = ''.join(filter(str.isalpha, text.lower()))
    if len(processed_text) % 2 != 0: processed_text += 'x'

    result = ""
    
    if encrypt:
        matrix = key_matrix
    else: # Decrypt
        det_inv = mod_inverse(det, 26)
        matrix = [
            [(det_inv * key_matrix[1][1]) % 26, (-det_inv * key_matrix[0][1] + 26) % 26],
            [(-det_inv * key_matrix[1][0] + 26) % 26, (det_inv * key_matrix[0][0]) % 26]
        ]
        
    for i in range(0, len(processed_text), 2):
        p1, p2 = ord(processed_text[i]) - ord('a'), ord(processed_text[i+1]) - ord('a')
        
        # Sửa lại công thức nhân ma trận theo chuẩn K * P (Matrix x Vector)
        c1 = (matrix[0][0] * p1 + matrix[0][1] * p2) % 26
        c2 = (matrix[1][0] * p1 + matrix[1][1] * p2) % 26
        
        result += chr(c1 + ord('a')) + chr(c2 + ord('a'))
    return result

# --- HÀM TIỆN ÍCH CHUNG ---

def kdf(password_bytes):
    #... (Giữ nguyên)
    salt = b'fixed_salt_for_demo_dont_use_in_prod'
    kdf_func = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf_func.derive(password_bytes)

def encrypt_data(key_or_password, data, algorithm="AES"):
    # ... (Phần logic AES, Caesar, Trans, Affine giữ nguyên)
    # Cập nhật lại logic gọi Hill
    if algorithm == "AES":
        salt = os.urandom(16); iv = os.urandom(16); key = kdf(key_or_password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()); encryptor = cipher.encryptor()
        pad_len = 16 - (len(data.encode()) % 16); padded_data = data.encode() + bytes([pad_len] * pad_len)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return b'\x01' + salt + iv + encrypted_data
    elif algorithm == "CAESAR":
        try: return b'\x02' + caesar_cipher(data, int(key_or_password), encrypt=True).encode('utf-8')
        except: return None
    elif algorithm == "TRANS":
        if not (len(set(key_or_password)) == len(key_or_password) and key_or_password.isalpha()): return None
        return b'\x03' + transposition_cipher(data, key_or_password, encrypt=True).encode('utf-8')
    elif algorithm == "AFFINE":
        try:
            parts = key_or_password.split(','); a, b = int(parts[0]), int(parts[1])
            if len(parts) != 2 or gcd(a, 26) != 1: return None
            return b'\x04' + affine_cipher(data, a, b, encrypt=True).encode('utf-8')
        except: return None
    elif algorithm == "HILL":
        try:
            parts = key_or_password.split(',')
            if len(parts) != 4: return None
            k = [int(p) for p in parts]
            key_matrix = [[k[0], k[1]], [k[2], k[3]]]
            # Bây giờ hill_cipher sẽ tự kiểm tra và báo lỗi nếu cần
            return b'\x05' + hill_cipher(data, key_matrix, encrypt=True).encode('utf-8')
        except: return None
    return None

def decrypt_data(key_or_password, encrypted_blob):
    try:
        algo_id, encrypted_data_raw = encrypted_blob[0], encrypted_blob[1:]
        if algo_id == 1:
            salt, iv, encrypted_data = encrypted_blob[1:17], encrypted_blob[17:33], encrypted_blob[33:]
            key = kdf(key_or_password.encode())
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()); decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            pad_len = padded_data[-1]
            return padded_data[:-pad_len].decode('utf-8') if pad_len <= 16 else None
        elif algo_id == 2:
            return caesar_cipher(encrypted_data_raw.decode('utf-8'), int(key_or_password), encrypt=False)
        elif algo_id == 3:
            if not (len(set(key_or_password)) == len(key_or_password) and key_or_password.isalpha()): return None
            return transposition_cipher(encrypted_data_raw.decode('utf-8'), key_or_password, encrypt=False)
        elif algo_id == 4:
            parts = key_or_password.split(','); a, b = int(parts[0]), int(parts[1])
            if len(parts) != 2 or gcd(a, 26) != 1: return None
            return affine_cipher(encrypted_data_raw.decode('utf-8'), a, b, encrypt=False)
        elif algo_id == 5:
            parts = key_or_password.split(',')
            if len(parts) != 4: return None
            k = [int(p) for p in parts]
            key_matrix = [[k[0], k[1]], [k[2], k[3]]]
            # Bây giờ hill_cipher sẽ tự kiểm tra và báo lỗi nếu cần
            return hill_cipher(encrypted_data_raw.decode('utf-8'), key_matrix, encrypt=False)
        return None
    except Exception as e:
        print(f"Error during decryption: {e}") # In lỗi ra console để debug
        return None
