import os
import math
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher as DesCipher, algorithms as DesAlgorithms, modes as DesModes
from cryptography.exceptions import InvalidTag

# --- CÁC HÀM HỖ TRỢ TOÁN HỌC ---
def gcd(a, b):
    while b: a, b = b, a % b
    return a

def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# --- 1. MÃ HÓA DỊCH VÒNG (CAESAR CIPHER) - ID 2 ---
def caesar_cipher(text, shift, encrypt=True):
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

# --- 3. MÃ HÓA HOÁN VỊ (TRANSPOSITION CIPHER) - ID 3 ---
def transposition_cipher(text, key, encrypt=True):
    if encrypt:
        num_cols = len(key)
        num_rows = math.ceil(len(text) / num_cols)
        # Sử dụng ký tự padding khác, ví dụ '\x00' (null byte), để tránh lỗi khi giải mã
        padded_text = text.ljust(num_rows * num_cols, '_') 
        grid = [padded_text[i:i+num_cols] for i in range(0, len(padded_text), num_cols)]
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        ciphertext = "".join(grid[row_idx][col_idx] for col_idx in key_order for row_idx in range(num_rows))
        return ciphertext
    else:
        num_cols = len(key)
        num_rows = math.ceil(len(text) / num_cols)
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        num_shaded_boxes = (num_cols * num_rows) - len(text)
        grid = [['' for _ in range(num_cols)] for _ in range(num_rows)]
        text_idx = 0
        for col_idx_sorted_order in range(num_cols):
            original_col_idx = key_order[col_idx_sorted_order]
            col_len = num_rows
            if original_col_idx >= num_cols - num_shaded_boxes and num_shaded_boxes > 0:
                col_len = num_rows - 1

            for row_idx in range(col_len):
                if text_idx < len(text):
                    grid[row_idx][original_col_idx] = text[text_idx]
                    text_idx += 1
        # Fix: đảm bảo loại bỏ ký tự padding '_'
        return "".join("".join(row) for row in grid).rstrip('_')

# --- 5. MÃ HÓA THAY THẾ AFFINE (AFFINE CIPHER) - ID 4 ---
def affine_cipher(text, key_a, key_b, encrypt=True):
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

# --- 5. MÃ HÓA THAY THẾ HILL (HILL CIPHER 2x2) - ID 5 ---
def hill_cipher(text, key_matrix, encrypt=True):
    det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) % 26
    if gcd(det, 26) != 1:
        raise ValueError("Khóa không hợp lệ (định thức không khả nghịch mod 26).")

    processed_text = ''.join(filter(str.isalpha, text.lower()))
    is_padded = len(processed_text) % 2 != 0 # Cờ kiểm tra padding
    if is_padded: processed_text += 'x'

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
        c1 = (matrix[0][0] * p1 + matrix[0][1] * p2) % 26
        c2 = (matrix[1][0] * p1 + matrix[1][1] * p2) % 26
        result += chr(c1 + ord('a')) + chr(c2 + ord('a'))
    
    # Fix: Loại bỏ ký tự padding 'x' khi giải mã
    if not encrypt and is_padded and result.endswith('x'):
        return result[:-1]

    return result

# --- 4. MÃ HÓA VIGENÈRE (VIGENÈRE CIPHER) - ID 7 ---
def vigenere_cipher(text, key, encrypt=True):
    result = ""
    key = ''.join(filter(str.isalpha, key)).upper()
    key_len = len(key)
    if key_len == 0:
        return text

    key_as_shifts = [ord(k) - ord('A') for k in key]
    key_idx = 0

    for char in text:
        if 'a' <= char <= 'z':
            start = ord('a')
            key_shift = key_as_shifts[key_idx % key_len]
            if not encrypt: key_shift = -key_shift 
            
            new_ord = (ord(char) - start + key_shift) % 26 + start
            result += chr(new_ord)
            
            key_idx += 1
        elif 'A' <= char <= 'Z':
            start = ord('A')
            key_shift = key_as_shifts[key_idx % key_len]
            if not encrypt: key_shift = -key_shift 
            
            new_ord = (ord(char) - start + key_shift) % 26 + start
            result += chr(new_ord)
            
            key_idx += 1
        else:
            result += char
    return result

# --- 6. MÃ HÓA DES (DATA ENCRYPTION STANDARD) - ID 6 ---
def des_cipher(key_bytes, data_bytes, encrypt=True):
    # Khóa phải là 24 bytes cho 3DES 3-Key
    if len(key_bytes) != 24:
        # Nếu key ngắn hơn 24 byte, dùng SHA256 để rút gọn và lặp lại
        hashed_key = hashlib.sha256(key_bytes).digest()
        key_24_bytes = (hashed_key * 3)[:24] # Lặp lại 3 lần và cắt thành 24 byte
        key_bytes = key_24_bytes
        
    if len(key_bytes) != 24:
        # Lỗi xảy ra khi băm vẫn không đủ (rất hiếm nếu key_bytes đủ lớn)
        raise ValueError("DES/3DES key must be exactly 24 bytes after derivation.")
    
    iv = os.urandom(8) # IV 8 bytes cho DES/3DES
    cipher = DesCipher(DesAlgorithms.TripleDES(key_bytes), DesModes.CBC(iv), backend=default_backend()) 
    
    if encrypt:
        encryptor = cipher.encryptor()
        pad_len = 8 - (len(data_bytes) % 8)
        padded_data = data_bytes + bytes([pad_len] * pad_len)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    else:
        iv_received = data_bytes[:8]
        ciphertext = data_bytes[8:]
        
        cipher_decrypt = DesCipher(DesAlgorithms.TripleDES(key_bytes), DesModes.CBC(iv_received), backend=default_backend())
        decryptor = cipher_decrypt.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        pad_len = padded_data[-1]
        if pad_len > 8: return None
        return padded_data[:-pad_len]

# --- HÀM HỖ TRỢ KEY DERIVATION ---
def kdf(password_bytes):
    salt = b'fixed_salt_for_demo_dont_use_in_prod'
    # Tăng iterations lên 600,000 để tăng bảo mật chống bruteforce
    kdf_func = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000, backend=default_backend())
    return kdf_func.derive(password_bytes)

# --- 7. MÃ HÓA AES (ADVANCED ENCRYPTION STANDARD) - ID 1 ---
# Logic tích hợp trong encrypt/decrypt_data

# --- 8. MÃ HÓA RSA (RIVEST-SHAMIR-ADLEMAN) - ID 8 ---
def rsa_encrypt_decrypt(data, private_key_password=None, encrypt=True):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    data_bytes = data.encode('utf-8')

    if encrypt:
        ciphertext = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        if private_key_password is None:
             raise ValueError("Phải cung cấp mật khẩu để bảo vệ Private Key của RSA.")
             
        # SỬ DỤNG BestAvailableEncryption để mã hóa Private Key bằng mật khẩu
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_password.encode('utf-8'))
        )
        return private_key_pem + b'::SPLIT::' + ciphertext
    else:
        pass

# --- 9. HÀM BĂM MD5 128 (MESSAGE-DIGEST ALGORITHM 5) - ID 9 ---
def hash_md5(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# --- 10. HÀM BĂM SHA 256 (SECURE HASHING ALGORITHM 256) - ID 10 ---
def hash_sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# --- HÀM TIỆN ÍCH CHUNG (ENCRYPT) ---

def encrypt_data(key_or_password, data, algorithm="AES"):
    try:
        if algorithm == "AES": # ID 1 (Đã nâng cấp lên AES-GCM)
            salt = os.urandom(16)
            key = kdf(key_or_password.encode()) # Khóa 32 byte
            nonce = os.urandom(12) # Nonce 12 byte cho GCM
            
            # Sử dụng GCM (Authenticated Encryption)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()) 
            encryptor = cipher.encryptor()
            
            encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
            tag = encryptor.tag # Lấy Authentication Tag (16 bytes)
            
            # Format mới: ID + Salt + Nonce + Tag + Ciphertext
            return b'\x01' + salt + nonce + tag + encrypted_data
        
        elif algorithm == "CAESAR": # ID 2
             return b'\x02' + caesar_cipher(data, int(key_or_password), encrypt=True).encode('utf-8')
             
        elif algorithm == "TRANS": # ID 3
             if not (len(set(key_or_password)) == len(key_or_password) and key_or_password.isalpha()): return None
             return b'\x03' + transposition_cipher(data, key_or_password.upper(), encrypt=True).encode('utf-8')
             
        elif algorithm == "AFFINE": # ID 4
             parts = key_or_password.split(','); a, b = int(parts[0]), int(parts[1])
             if len(parts) != 2 or gcd(a, 26) != 1: return None
             return b'\x04' + affine_cipher(data, a, b, encrypt=True).encode('utf-8')
             
        elif algorithm == "HILL": # ID 5
             parts = key_or_password.split(',')
             if len(parts) != 4: return None
             k = [int(p) for p in parts]
             key_matrix = [[k[0], k[1]], [k[2], k[3]]]
             return b'\x05' + hill_cipher(data, key_matrix, encrypt=True).encode('utf-8')
             
        elif algorithm == "DES": # ID 6
             key_bytes = key_or_password.encode('utf-8')
             encrypted_data_raw = des_cipher(key_bytes, data.encode('utf-8'), encrypt=True)
             return b'\x06' + encrypted_data_raw
             
        elif algorithm == "VIGENERE": # ID 7
             cleaned_key = ''.join(filter(str.isalpha, key_or_password))
             if not cleaned_key: return None
             return b'\x07' + vigenere_cipher(data, cleaned_key, encrypt=True).encode('utf-8')
             
        elif algorithm == "RSA": # ID 8 (Pass mật khẩu để bảo vệ Private Key)
            rsa_blob = rsa_encrypt_decrypt(data, private_key_password=key_or_password, encrypt=True)
            return b'\x08' + rsa_blob
            
        elif algorithm == "MD5": # ID 9
             return b'\x09' + hash_md5(data).encode('utf-8')
             
        elif algorithm == "SHA256": # ID 10
             return b'\x0a' + hash_sha256(data).encode('utf-8')
             
        return None
    except Exception as e:
        return None

# --- HÀM TIỆN ÍCH CHUNG (DECRYPT) ---
def decrypt_data(key_or_password, encrypted_blob, rsa_key_password=None):
    try:
        algo_id, encrypted_data_raw = encrypted_blob[0], encrypted_blob[1:]
        
        if algo_id == 1: # AES (GCM Decrypt)
            # Lấy Salt (16), Nonce (12), Tag (16), và Ciphertext
            salt, nonce, tag, encrypted_data = encrypted_blob[1:17], encrypted_blob[17:29], encrypted_blob[29:45], encrypted_blob[45:]
            key = kdf(key_or_password.encode())
            
            # Sử dụng GCM, bao gồm Tag để xác thực
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Giải mã và xác thực. Nếu tag không khớp, .finalize() sẽ raise InvalidTag
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            return decrypted_data.decode('utf-8')
            
        elif algo_id == 2: # CAESAR
             return caesar_cipher(encrypted_data_raw.decode('utf-8'), int(key_or_password), encrypt=False)
             
        elif algo_id == 3: # TRANS
             if not (len(set(key_or_password)) == len(key_or_password) and key_or_password.isalpha()): return None
             # Fix: loại bỏ padding '_'
             return transposition_cipher(encrypted_data_raw.decode('utf-8'), key_or_password.upper(), encrypt=False).rstrip('_') 
             
        elif algo_id == 4: # AFFINE
             parts = key_or_password.split(','); a, b = int(parts[0]), int(parts[1])
             if len(parts) != 2 or gcd(a, 26) != 1: return None
             return affine_cipher(encrypted_data_raw.decode('utf-8'), a, b, encrypt=False)
             
        elif algo_id == 5: # HILL
             parts = key_or_password.split(',')
             if len(parts) != 4: return None
             k = [int(p) for p in parts]
             key_matrix = [[k[0], k[1]], [k[2], k[3]]]
             # Fix: hill_cipher tự loại bỏ padding 'x'
             return hill_cipher(encrypted_data_raw.decode('utf-8'), key_matrix, encrypt=False)
             
        elif algo_id == 6: # DES
             key_bytes = key_or_password.encode('utf-8')
             decrypted_bytes = des_cipher(key_bytes, encrypted_data_raw, encrypt=False)
             return decrypted_bytes.decode('utf-8') if decrypted_bytes is not None else None
             
        elif algo_id == 7: # VIGENERE
             cleaned_key = ''.join(filter(str.isalpha, key_or_password))
             if not cleaned_key: return None
             return vigenere_cipher(encrypted_data_raw.decode('utf-8'), cleaned_key, encrypt=False)
             
        elif algo_id == 8: # RSA
            if b'::SPLIT::' not in encrypted_data_raw: return None
            private_key_pem, ciphertext = encrypted_data_raw.split(b'::SPLIT::', 1)
            
            # RSA Khóa riêng đã được mã hóa, cần mật khẩu (rsa_key_password) để tải
            if rsa_key_password is None: return None 
            
            private_key = serialization.load_pem_private_key(
                private_key_pem, 
                password=rsa_key_password.encode('utf-8'), # <<< Truyền mật khẩu bảo vệ khóa
                backend=default_backend()
            )
            
            decrypted_data = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data.decode('utf-8')
            
        elif algo_id == 9: # MD5 (Không giải mã)
            return f"Không thể giải mã MD5. Giá trị băm: {encrypted_data_raw.decode('utf-8')}"
        elif algo_id == 10: # SHA256 (Không giải mã)
            return f"Không thể giải mã SHA-256. Giá trị băm: {encrypted_data_raw.decode('utf-8')}"
             
        return None
    except InvalidTag:
        # Lỗi InvalidTag từ AES-GCM khi dữ liệu bị giả mạo hoặc mật khẩu sai
        return None
    except Exception as e:
        # Bắt các lỗi khác (lỗi định dạng khóa, lỗi RSA, v.v.)
        return None