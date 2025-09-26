import math

def caesar_encrypt(text, shift):
    """
    Mã hóa văn bản bằng thuật toán Caesar (Dịch vòng).
    Chỉ dịch chuyển các chữ cái (a-z, A-Z) và giữ nguyên các ký tự khác.
    """
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            # Công thức dịch chuyển vòng
            shifted_char = chr((ord(char) - start + shift) % 26 + start)
            result += shifted_char
        else:
            # Giữ nguyên các ký tự không phải chữ cái (số, dấu câu,...)
            result += char
    return result

def transposition_encrypt(text, key):
    """
    Mã hóa văn bản bằng thuật toán hoán vị cột đơn giản.
    """
    key_length = len(key)
    # Tính số cột
    num_cols = key_length
    # Tính số hàng cần thiết
    num_rows = math.ceil(len(text) / num_cols)
    
    # Thêm ký tự đệm (ví dụ: ' ') nếu văn bản không lấp đầy lưới
    padded_text = text.ljust(num_rows * num_cols)
    
    # Tạo lưới (grid)
    grid = [''] * num_rows
    for i in range(num_rows):
        grid[i] = list(padded_text[i * num_cols : (i + 1) * num_cols])

    # Sắp xếp thứ tự các cột dựa trên khóa
    key_order = sorted(range(key_length), key=lambda k: key[k])
    
    # Đọc các cột theo thứ tự đã sắp xếp để lấy bản mã
    ciphertext = ""
    for col_index in key_order:
        for row_index in range(num_rows):
            ciphertext += grid[row_index][col_index]
            
    return ciphertext
