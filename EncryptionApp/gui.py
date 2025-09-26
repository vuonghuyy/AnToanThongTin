import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from . import ciphers # Import tương đối từ cùng package 'src'

class App(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Công Cụ Mã Hóa")
        self.geometry("600x650")
        self.resizable(False, False)

        # --- Frame chính ---
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(expand=True, fill=BOTH)

        # --- Tiêu đề ---
        title_label = ttk.Label(main_frame, text="Trình Mã Hóa Văn Bản", font=("Helvetica", 18, "bold"), bootstyle="primary")
        title_label.pack(pady=(0, 20))

        # --- Lựa chọn thuật toán ---
        algo_frame = ttk.Frame(main_frame)
        algo_frame.pack(fill=X, pady=5)
        
        ttk.Label(algo_frame, text="1. Chọn thuật toán:", font=("Helvetica", 11, "bold")).pack(side=LEFT, padx=(0, 10))
        
        self.algorithm_var = ttk.StringVar()
        self.algorithms = ["Mã hóa Dịch vòng (Caesar)", "Mã hóa Hoán vị (Transposition)"]
        algorithm_menu = ttk.Combobox(
            algo_frame,
            textvariable=self.algorithm_var,
            values=self.algorithms,
            state="readonly",
            bootstyle="info"
        )
        algorithm_menu.pack(expand=True, fill=X)
        algorithm_menu.set("--- Chọn thuật toán ---")

        # --- Nhập liệu (Plaintext) ---
        ttk.Label(main_frame, text="2. Nhập văn bản gốc:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(15, 5))
        self.input_text = ttk.Text(main_frame, height=8, font=("Helvetica", 10))
        self.input_text.pack(fill=X)

        # --- Nhập khóa/độ dịch chuyển ---
        ttk.Label(main_frame, text="3. Nhập khóa / độ dịch chuyển:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(15, 5))
        self.key_entry = ttk.Entry(main_frame, font=("Helvetica", 10), bootstyle="info")
        self.key_entry.pack(fill=X)

        # --- Nút thực thi ---
        encrypt_button = ttk.Button(main_frame, text="TIẾN HÀNH MÃ HÓA", command=self.execute_encryption, bootstyle="success")
        encrypt_button.pack(pady=20, ipady=5, fill=X)

        # --- Kết quả (Ciphertext) ---
        ttk.Label(main_frame, text="4. Kết quả mã hóa:", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(15, 5))
        self.output_text = ttk.Text(main_frame, height=8, font=("Helvetica", 10), state="disabled")
        self.output_text.pack(fill=X)

        # --- Nhãn trạng thái ---
        self.status_label = ttk.Label(main_frame, text="Sẵn sàng...", font=("Helvetica", 10, "italic"), bootstyle="info")
        self.status_label.pack(anchor=W, pady=(10, 0))

    def execute_encryption(self):
        algo = self.algorithm_var.get()
        plaintext = self.input_text.get("1.0", END).strip()
        key = self.key_entry.get().strip()

        # --- Kiểm tra đầu vào ---
        if "---" in algo:
            self.status_label.config(text="Lỗi: Vui lòng chọn một thuật toán!", bootstyle="danger")
            return
        if not plaintext:
            self.status_label.config(text="Lỗi: Vui lòng nhập văn bản cần mã hóa!", bootstyle="danger")
            return
        if not key:
            self.status_label.config(text="Lỗi: Vui lòng nhập khóa hoặc độ dịch chuyển!", bootstyle="danger")
            return

        ciphertext = ""
        try:
            if "Dịch vòng" in algo:
                shift = int(key) # Chuyển khóa sang số nguyên
                ciphertext = ciphers.caesar_encrypt(plaintext, shift)
            elif "Hoán vị" in algo:
                ciphertext = ciphers.transposition_encrypt(plaintext, key)
            
            # --- Hiển thị kết quả ---
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", END)
            self.output_text.insert("1.0", ciphertext)
            self.output_text.config(state="disabled")
            self.status_label.config(text="Mã hóa thành công!", bootstyle="success")

        except ValueError:
            self.status_label.config(text="Lỗi: Độ dịch chuyển cho Caesar phải là một con số!", bootstyle="danger")
        except Exception as e:
            self.status_label.config(text=f"Lỗi không xác định: {e}", bootstyle="danger")
