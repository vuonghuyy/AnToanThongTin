import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import math

# --- CÁC THUẬT TOÁN MÃ HÓA CỔ ĐIỂN (CHỈ DÙNG CHO MỤC ĐÍCH THAM KHẢO) ---

def caesar_cipher(text, shift, encrypt=True):
    """Mã hóa hoặc giải mã Caesar."""
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            start = ord('a')
            shift_amount = shift if encrypt else -shift
            result += chr((ord(char) - start + shift_amount) % 26 + start)
        elif 'A' <= char <= 'Z':
            start = ord('A')
            shift_amount = shift if encrypt else -shift
            result += chr((ord(char) - start + shift_amount) % 26 + start)
        else:
            result += char
    return result

def transposition_cipher(text, key, encrypt=True):
    """Mã hóa hoặc giải mã hoán vị cột."""
    key_map = sorted([(char, i) for i, char in enumerate(key)])
    key_order = [i for char, i in key_map]
    
    if encrypt:
        num_cols = len(key)
        num_rows = math.ceil(len(text) / num_cols)
        # Thêm ký tự đệm nếu cần
        text += '_' * (num_rows * num_cols - len(text))
        grid = [text[i:i+num_cols] for i in range(0, len(text), num_cols)]
        
        ciphertext = ""
        for col_idx in key_order:
            for row_idx in range(num_rows):
                ciphertext += grid[row_idx][col_idx]
        return ciphertext
    else: # Decrypt
        num_cols = len(key)
        num_rows = math.ceil(len(text) / num_cols)
        num_shaded_boxes = (num_cols * num_rows) - len(text)
        
        grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        
        # Đánh dấu các ô bị tô bóng (shaded)
        for i in range(num_cols - num_shaded_boxes, num_cols):
            grid[num_rows-1][i] = '_'

        text_idx = 0
        for col_idx in key_order:
            for row_idx in range(num_rows):
                if grid[row_idx][col_idx] != '_':
                    grid[row_idx][col_idx] = text[text_idx]
                    text_idx += 1
        
        plaintext = ""
        # Đọc lại theo thứ tự ban đầu của cột
        original_order_map = sorted([(original_idx, char) for char, original_idx in key_map])
        
        # Sắp xếp lại grid theo thứ tự cột ban đầu
        decrypted_grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        for i, col_idx in enumerate(key_order):
            for row in range(num_rows):
                decrypted_grid[row][col_idx] = grid[row][i]
        
        # Đọc văn bản từ grid đã sắp xếp lại
        plaintext = ""
        for row in range(num_rows):
            for col in range(num_cols):
                 plaintext += decrypted_grid[row][original_order_map[col][0]]
        
        # Xây dựng lại grid theo thứ tự giải mã
        temp_grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        text_ptr = 0
        for col_idx in key_order:
             for row_idx in range(num_rows):
                  if not (row_idx == num_rows - 1 and col_idx >= num_cols - num_shaded_boxes):
                       temp_grid[row_idx][col_idx] = text[text_ptr]
                       text_ptr += 1

        plaintext = ""
        for row in temp_grid:
             plaintext += "".join(row)

        return plaintext.rstrip('_')

# --- HÀM TIỆN ÍCH VÀ MÃ HÓA AES HIỆN ĐẠI ---

def kdf(password_bytes):
    """Key Derivation Function."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'fixed_salt_for_demo', # Sử dụng salt cố định cho mục đích demo
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)

def encrypt_data(key_or_password, data, algorithm="AES"):
    """
    Hàm chính để mã hóa dữ liệu.
    - Đối với AES, key_or_password là mật khẩu.
    - Đối với Caesar/Trans, key_or_password là khóa tương ứng (dưới dạng chuỗi).
    """
    if algorithm == "AES":
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = kdf(key_or_password.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Padding dữ liệu
        pad_len = 16 - (len(data.encode()) % 16)
        padded_data = data.encode() + bytes([pad_len] * pad_len)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return b'\x01' + salt + iv + encrypted_data # \x01 cho AES

    elif algorithm == "CAESAR":
        try:
            shift = int(key_or_password)
            encrypted_data = caesar_cipher(data, shift, encrypt=True).encode('utf-8')
            return b'\x02' + encrypted_data # \x02 cho Caesar
        except (ValueError, TypeError):
            return None # Khóa không hợp lệ

    elif algorithm == "TRANS":
        key = key_or_password
        if not (len(set(key)) == len(key) and key.isalpha()):
             return None # Khóa không hợp lệ
        encrypted_data = transposition_cipher(data, key, encrypt=True).encode('utf-8')
        return b'\x03' + encrypted_data # \x03 cho Transposition
    
    return None

def decrypt_data(key_or_password, encrypted_blob):
    """
    Hàm chính để giải mã dữ liệu.
    - Đối với AES, key_or_password là mật khẩu.
    - Đối với Caesar/Trans, key_or_password là khóa tương ứng (dưới dạng chuỗi).
    """
    try:
        algo_id = encrypted_blob[0]
        
        if algo_id == 1: # AES
            salt = encrypted_blob[1:17]
            iv = encrypted_blob[17:33]
            encrypted_data = encrypted_blob[33:]
            
            key = kdf(key_or_password.encode())
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            pad_len = padded_data[-1]
            if pad_len > 16: return None # Lỗi padding
            
            return padded_data[:-pad_len].decode('utf-8')

        elif algo_id == 2: # Caesar
            shift = int(key_or_password)
            encrypted_data = encrypted_blob[1:].decode('utf-8')
            return caesar_cipher(encrypted_data, shift, encrypt=False)

        elif algo_id == 3: # Transposition
            key = key_or_password
            if not (len(set(key)) == len(key) and key.isalpha()):
                 return None # Khóa không hợp lệ
            encrypted_data = encrypted_blob[1:].decode('utf-8')
            return transposition_cipher(encrypted_data, key, encrypt=False)
            
        return None
    except Exception:
        return None

