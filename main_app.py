import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, font
import os
import threading
import time
import psutil
import crypto_utils
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import random
import string
import base64

class PasswordSafeApp(ttk.Window):
    def __init__(self):
        # Sử dụng theme 'superhero' cho giao diện hiện đại
        super().__init__(themename="superhero")
        
        self.title("Password Safe - Két Sắt Mật Khẩu")
        self.geometry("1100x700")
        self.center_window()

        # Lưu trữ đường dẫn file hiện tại
        self.current_file_path = None
        self.usb_drive_path = None
        
        self.create_widgets()

    def center_window(self):
        """Canh giữa cửa sổ ứng dụng trên màn hình."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(expand=True, fill=BOTH)

        # --- KHUNG CHỨA CÁC NÚT ĐIỀU KHIỂN ---
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=X, pady=(0, 15))

        # --- Các nút hành động (với style đậm và rõ ràng hơn) ---
        self.open_button = ttk.Button(control_frame, text=" Mở File .psafe", command=self.open_encrypted_file, bootstyle="secondary", width=15)
        self.open_button.pack(side=LEFT, padx=(0, 10))

        self.import_txt_button = ttk.Button(control_frame, text=" Nhập từ .txt", command=self.import_from_txt, bootstyle="info", width=15)
        self.import_txt_button.pack(side=LEFT, padx=(0, 10))

        self.generate_pass_button = ttk.Button(control_frame, text=" Tạo Mật Khẩu", command=self.open_password_generator, bootstyle="info", width=15)
        self.generate_pass_button.pack(side=LEFT, padx=(0, 10))

        self.preview_button = ttk.Button(control_frame, text="Xem Mã Hóa", command=self.preview_encryption, bootstyle="warning", width=15)
        self.preview_button.pack(side=LEFT, padx=(0, 10))

        self.save_button = ttk.Button(control_frame, text=" Lưu & Mã Hóa", command=self.save_encrypted_file, bootstyle="primary", width=15)
        self.save_button.pack(side=LEFT, padx=(0, 10))

        self.export_usb_button = ttk.Button(control_frame, text=" Xuất Ra USB", command=self.export_to_usb, bootstyle="success", width=15)
        self.export_usb_button.pack(side=LEFT, padx=(0, 10))
        
        # --- KHUNG LỰA CHỌN THUẬT TOÁN ---
        algo_frame = ttk.Labelframe(main_frame, text=" Thuật Toán Mã Hóa ", padding=15)
        algo_frame.pack(fill=X, pady=(0, 15))
        
        self.algo_var = tk.StringVar(value="AES")

        aes_radio = ttk.Radiobutton(algo_frame, text="AES (Bảo mật cao)", variable=self.algo_var, value="AES", bootstyle="info")
        aes_radio.pack(side=LEFT, padx=(0, 20))
        
        caesar_radio = ttk.Radiobutton(algo_frame, text="Caesar (Không an toàn)", variable=self.algo_var, value="CAESAR", bootstyle="warning")
        caesar_radio.pack(side=LEFT, padx=(0, 20))

        trans_radio = ttk.Radiobutton(algo_frame, text="Hoán vị (Không an toàn)", variable=self.algo_var, value="TRANS", bootstyle="warning")
        trans_radio.pack(side=LEFT)

        # --- VÙNG NHẬP VĂN BẢN (SỬ DỤNG NOTEBOOK) ---
        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill=BOTH)

        # Tab 1: Soạn thảo (Bản rõ)
        tab_plain = ttk.Frame(notebook, padding=0)
        self.text_area = tk.Text(
            tab_plain, wrap="word", bg="#2b3e50", fg="#ffffff",
            insertbackground="#ffffff", undo=True, font=("Segoe UI", 12),
            bd=0, highlightthickness=0, padx=10, pady=10,
        )
        self.text_area.pack(expand=True, fill=BOTH)
        notebook.add(tab_plain, text="Soạn Thảo (Bản Rõ)")

        # Tab 2: Xem trước (Bản mã hóa)
        tab_encrypted = ttk.Frame(notebook, padding=0)
        self.encrypted_text_area = tk.Text(
            tab_encrypted, wrap="word", bg="#202020", fg="#a0a0a0",
            insertbackground="#ffffff", font=("Courier New", 12),
            bd=0, highlightthickness=0, padx=10, pady=10, state="disabled"
        )
        self.encrypted_text_area.pack(expand=True, fill=BOTH)
        notebook.add(tab_encrypted, text="Xem Trước (Bản Mã Hóa)")
        self.notebook = notebook


        # --- THANH TRẠNG THÁI ---
        self.status_bar = ttk.Label(self, text="Sẵn sàng", padding=5, bootstyle="primary-inverse", anchor=W)
        self.status_bar.pack(side=BOTTOM, fill=X)
    
    def update_encrypted_view(self, content_bytes):
        """Cập nhật nội dung cho tab mã hóa."""
        self.encrypted_text_area.config(state="normal")
        self.encrypted_text_area.delete(1.0, tk.END)
        # Hiển thị dưới dạng Base64 để dễ đọc
        encoded_content = base64.b64encode(content_bytes).decode('utf-8')
        self.encrypted_text_area.insert(tk.END, encoded_content)
        self.encrypted_text_area.config(state="disabled")

    def preview_encryption(self):
        """Mã hóa nội dung hiện tại và hiển thị trong tab xem trước."""
        content = self.text_area.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Nội dung rỗng", "Không có gì để mã hóa.", parent=self)
            return
        
        key_or_pass = self.prompt_for_key_or_password()
        if not key_or_pass:
            return

        selected_algorithm = self.algo_var.get()
        if selected_algorithm != "AES":
            if not messagebox.askokcancel("Cảnh Báo Bảo Mật", f"Bạn đang sử dụng thuật toán '{selected_algorithm}' KHÔNG AN TOÀN. Chỉ nên dùng cho mục đích thử nghiệm. Bạn có muốn tiếp tục?", parent=self):
                return
        
        encrypted_blob = crypto_utils.encrypt_data(key_or_pass, content, selected_algorithm)
        if encrypted_blob:
            self.update_encrypted_view(encrypted_blob)
            self.status_bar.config(text=f"Đã xem trước mã hóa với thuật toán {selected_algorithm}.")
            self.notebook.select(1) # Chuyển sang tab mã hóa
        else:
            messagebox.showerror("Lỗi Mã Hóa", "Quá trình mã hóa xem trước đã thất bại. Có thể do khóa không hợp lệ.", parent=self)

    def open_password_generator(self):
        """Mở cửa sổ tạo mật khẩu ngẫu nhiên."""
        gen_window = ttk.Toplevel(self)
        gen_window.title("Trình Tạo Mật Khẩu")
        gen_window.geometry("600x450")
        gen_window.transient(self)
        gen_window.grab_set()
        
        # --- Các biến điều khiển ---
        length_var = tk.IntVar(value=16)
        use_upper_var = tk.BooleanVar(value=True)
        use_lower_var = tk.BooleanVar(value=True)
        use_digits_var = tk.BooleanVar(value=True)
        use_symbols_var = tk.BooleanVar(value=True)
        password_var = tk.StringVar()

        def update_length_label(val):
            length_label.config(text=f"Độ dài mật khẩu: {int(float(val))}")

        def generate_password():
            length = length_var.get()
            char_pool = ""
            if use_upper_var.get(): char_pool += string.ascii_uppercase
            if use_lower_var.get(): char_pool += string.ascii_lowercase
            if use_digits_var.get(): char_pool += string.digits
            if use_symbols_var.get(): char_pool += string.punctuation
            
            if not char_pool:
                messagebox.showwarning("Lỗi", "Vui lòng chọn ít nhất một loại ký tự.", parent=gen_window)
                return
            
            password = "".join(random.choices(char_pool, k=length))
            password_var.set(password)
        
        def copy_to_clipboard():
            self.clipboard_clear()
            self.clipboard_append(password_var.get())
            self.status_bar.config(text="Đã sao chép mật khẩu vào clipboard!")

        def insert_password():
            self.text_area.insert(tk.END, password_var.get() + "\n")
            gen_window.destroy()

        # --- Giao diện cửa sổ generator ---
        gen_frame = ttk.Frame(gen_window, padding=20)
        gen_frame.pack(expand=True, fill=BOTH)

        # --- Kết quả ---
        result_frame = ttk.Frame(gen_frame)
        result_frame.pack(fill=X, pady=(0, 15))
        
        password_entry = ttk.Entry(result_frame, textvariable=password_var, font=("Courier New", 12), bootstyle="success", state="readonly")
        password_entry.pack(side=LEFT, expand=True, fill=X, ipady=5)
        
        copy_button = ttk.Button(result_frame, text="Sao chép", command=copy_to_clipboard, bootstyle="secondary")
        copy_button.pack(side=LEFT, padx=(10, 0))

        # --- Tùy chọn ---
        options_frame = ttk.Labelframe(gen_frame, text=" Tùy chọn ", padding=15)
        options_frame.pack(fill=X, pady=(0, 15))

        # Độ dài
        length_label = ttk.Label(options_frame, text=f"Độ dài mật khẩu: {length_var.get()}")
        length_label.pack(anchor=W)
        length_slider = ttk.Scale(options_frame, from_=8, to=64, variable=length_var, command=update_length_label)
        length_slider.pack(fill=X, pady=(5, 15))

        # Loại ký tự
        upper_check = ttk.Checkbutton(options_frame, text="Bao gồm chữ hoa (A-Z)", variable=use_upper_var, bootstyle="primary-round-toggle")
        upper_check.pack(anchor=W, pady=2)
        lower_check = ttk.Checkbutton(options_frame, text="Bao gồm chữ thường (a-z)", variable=use_lower_var, bootstyle="primary-round-toggle")
        lower_check.pack(anchor=W, pady=2)
        digits_check = ttk.Checkbutton(options_frame, text="Bao gồm số (0-9)", variable=use_digits_var, bootstyle="primary-round-toggle")
        digits_check.pack(anchor=W, pady=2)
        symbols_check = ttk.Checkbutton(options_frame, text="Bao gồm ký tự đặc biệt (!@#$%)", variable=use_symbols_var, bootstyle="primary-round-toggle")
        symbols_check.pack(anchor=W, pady=2)

        # --- Nút hành động ---
        action_frame = ttk.Frame(gen_frame)
        action_frame.pack(fill=X, pady=(10, 0))

        generate_button = ttk.Button(action_frame, text="Tạo mới", command=generate_password, bootstyle="info")
        generate_button.pack(side=LEFT, expand=True, fill=X, padx=(0, 5))

        insert_button = ttk.Button(action_frame, text="Chèn vào", command=insert_password, bootstyle="success")
        insert_button.pack(side=LEFT, expand=True, fill=X, padx=(5, 0))
        
        generate_password() # Tạo một mật khẩu ban đầu khi mở

    def import_from_txt(self):
        """Mở một file .txt và hiển thị nội dung."""
        if len(self.text_area.get(1.0, tk.END).strip()) > 0:
            if not messagebox.askyesno("Cảnh Báo", "Thao tác này sẽ xóa nội dung hiện tại chưa được lưu. Bạn có muốn tiếp tục?"):
                return
        filepath = filedialog.askopenfilename(
            title="Chọn file .txt để nhập",
            filetypes=[("Text Files", "*.txt"), ("All files", "*.*")]
        )
        if not filepath:
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, content)
            # Xóa nội dung mã hóa cũ
            self.encrypted_text_area.config(state="normal")
            self.encrypted_text_area.delete(1.0, tk.END)
            self.encrypted_text_area.config(state="disabled")
            self.current_file_path = None 
            self.status_bar.config(text=f"Đã nhập nội dung từ: {os.path.basename(filepath)}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể đọc file .txt: {e}")

    def prompt_for_key_or_password(self):
        """Hộp thoại yêu cầu người dùng nhập mật khẩu hoặc khóa tùy chỉnh."""
        selected_algorithm = self.algo_var.get()
        title = "Yêu Cầu Nhập Liệu"
        prompt = ""
        key = None

        if selected_algorithm == "AES":
            title = "Nhập Mật Khẩu Chủ"
            prompt = "Vui lòng nhập mật khẩu chủ của bạn:"
            key = simpledialog.askstring(title, prompt, show='*', parent=self)

        elif selected_algorithm == "CAESAR":
            title = "Nhập Khóa Dịch Chuyển"
            prompt = "Vui lòng nhập khóa là một số nguyên (ví dụ: 3):"
            input_val = simpledialog.askstring(title, prompt, parent=self)
            if input_val:
                try:
                    int(input_val) # Chỉ để kiểm tra
                    key = input_val # Giữ ở dạng chuỗi để truyền đi
                except ValueError:
                    messagebox.showerror("Khóa không hợp lệ", "Khóa cho mã hóa Caesar phải là một số nguyên.", parent=self)
                    return None
        
        elif selected_algorithm == "TRANS":
            title = "Nhập Khóa Hoán Vị"
            prompt = "Nhập khóa là một chuỗi chữ cái không lặp lại (ví dụ: 'PYTHON'):"
            input_val = simpledialog.askstring(title, prompt, parent=self)
            if input_val:
                if len(set(input_val)) == len(input_val) and input_val.isalpha():
                    key = input_val.upper() # Luôn dùng chữ hoa cho khóa
                else:
                    messagebox.showerror("Khóa không hợp lệ", "Khóa cho mã hóa Hoán vị phải là một chuỗi các chữ cái không lặp lại.", parent=self)
                    return None
        
        return key

    def open_encrypted_file(self):
        """Mở và giải mã một file."""
        filepath = filedialog.askopenfilename(
            title="Chọn file để giải mã",
            filetypes=[("Password Safe Files", "*.psafe"), ("All files", "*.*")]
        )
        if not filepath:
            return

        # Đọc trước thuật toán từ file để biết cần hỏi khóa gì
        try:
            with open(filepath, 'rb') as f:
                file_content = f.read()
                if not file_content:
                    messagebox.showerror("Lỗi", "File rỗng.", parent=self)
                    return
                algo_id = file_content[0]
                if algo_id == 2: self.algo_var.set("CAESAR")
                elif algo_id == 3: self.algo_var.set("TRANS")
                else: self.algo_var.set("AES")
        except Exception as e:
            messagebox.showerror("Lỗi Đọc File", f"Không thể đọc file: {e}", parent=self)
            return

        key_or_pass = self.prompt_for_key_or_password()
        if not key_or_pass:
            messagebox.showwarning("Hủy Bỏ", "Đã hủy thao tác vì không có mật khẩu/khóa.", parent=self)
            return
        
        decrypted_content = crypto_utils.decrypt_data(key_or_pass, file_content)
        
        if decrypted_content is not None:
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, decrypted_content)
            self.update_encrypted_view(file_content)
            self.current_file_path = filepath
            self.status_bar.config(text=f"Đã mở và giải mã thành công: {os.path.basename(filepath)}")
            self.notebook.select(0) # Chuyển về tab soạn thảo
        else:
            messagebox.showerror("Lỗi Giải Mã", "Mật khẩu/khóa không đúng hoặc file đã bị hỏng.", parent=self)

    def save_encrypted_file(self):
        """Lưu nội dung vào file đã mã hóa."""
        content = self.text_area.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Nội dung rỗng", "Không có gì để lưu.")
            return
        filepath = filedialog.asksaveasfilename(
            title="Lưu file mã hóa",
            defaultextension=".psafe",
            filetypes=[("Password Safe Files", "*.psafe"), ("All files", "*.*")]
        )
        if not filepath:
            return
            
        key_or_pass = self.prompt_for_key_or_password()
        if not key_or_pass:
            messagebox.showwarning("Hủy Bỏ", "Đã hủy thao tác vì không có mật khẩu/khóa.")
            return
        
        selected_algorithm = self.algo_var.get()
        if selected_algorithm != "AES":
            if not messagebox.askokcancel("Cảnh Báo Bảo Mật", f"Bạn đang sử dụng thuật toán '{selected_algorithm}' KHÔNG AN TOÀN. Dữ liệu có thể dễ dàng bị giải mã. Chỉ nên dùng cho mục đích thử nghiệm. Bạn có muốn tiếp tục?"):
                return

        encrypted_blob = crypto_utils.encrypt_data(key_or_pass, content, selected_algorithm)
        if encrypted_blob:
            try:
                with open(filepath, 'wb') as f:
                    f.write(encrypted_blob)
                self.current_file_path = filepath
                self.update_encrypted_view(encrypted_blob)
                self.status_bar.config(text=f"Đã mã hóa ({selected_algorithm}) và lưu thành công: {os.path.basename(filepath)}")
                messagebox.showinfo("Thành Công", "Dữ liệu đã được mã hóa và lưu an toàn!")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể ghi file: {e}")
        else:
            messagebox.showerror("Lỗi Mã Hóa", "Quá trình mã hóa đã thất bại. Có thể do khóa không hợp lệ.")

    def find_usb_drives(self):
        """Tìm các ổ đĩa USB."""
        drives = []
        for partition in psutil.disk_partitions():
            if 'removable' in partition.opts or 'cdrom' in partition.opts:
                drives.append(partition.mountpoint)
        return drives

    def export_to_usb(self):
        """Xuất file mã hóa và file bat khởi động ra USB."""
        content = self.text_area.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Nội dung rỗng", "Không có nội dung để xuất ra USB.")
            return
        usb_drives = self.find_usb_drives()
        if not usb_drives:
            messagebox.showerror("Không Tìm Thấy USB", "Vui lòng cắm USB và thử lại.")
            return
        usb_path = usb_drives[0]

        key_or_pass = self.prompt_for_key_or_password()
        if not key_or_pass:
            return

        selected_algorithm = self.algo_var.get()
        if selected_algorithm != "AES":
            if not messagebox.askokcancel("Cảnh Báo Bảo Mật", f"Bạn đang sử dụng thuật toán '{selected_algorithm}' KHÔNG AN TOÀN. Dữ liệu có thể dễ dàng bị giải mã. Chỉ nên dùng cho mục đích thử nghiệm. Bạn có muốn tiếp tục?"):
                return

        encrypted_blob = crypto_utils.encrypt_data(key_or_pass, content, selected_algorithm)
        if encrypted_blob:
            encrypted_file_path = os.path.join(usb_path, "passwords.psafe")
            try:
                with open(encrypted_file_path, 'wb') as f:
                    f.write(encrypted_blob)
            except Exception as e:
                messagebox.showerror("Lỗi Ghi File", f"Không thể lưu file dữ liệu vào USB: {e}")
                return
        else:
            messagebox.showerror("Lỗi Mã Hóa", "Quá trình mã hóa đã thất bại. Có thể do khóa không hợp lệ.")
            return

        bat_content = f"""@echo off
rem File nay dung de khoi dong ung dung Password Safe
rem Dam bao ban da chep cac file main_app.py va crypto_utils.py vao cung thu muc tren USB
echo Starting Password Safe...
python main_app.py
pause
"""
        bat_file_path = os.path.join(usb_path, "start_app.bat")
        try:
            with open(bat_file_path, 'w') as f:
                f.write(bat_content)
        except Exception as e:
            messagebox.showerror("Lỗi Tạo File BAT", f"Không thể tạo file khởi động trên USB: {e}")
            return
        
        self.usb_drive_path = usb_path
        messagebox.showinfo(
            "Thành Công!",
            f"Đã xuất dữ liệu thành công ra USB ({usb_path})."
        )
        # Chỉ bắt đầu giám sát USB SAU KHI đã xuất file thành công
        self.start_usb_monitor()

    def monitor_usb(self):
        """
        Hàm chạy trong một luồng riêng để giám sát sự tồn tại của USB.
        Nếu USB bị rút ra, ứng dụng sẽ tự động đóng.
        """
        if not self.usb_drive_path:
            return
        initial_drives = self.find_usb_drives()
        if self.usb_drive_path not in initial_drives:
            return
        while True:
            time.sleep(3)
            current_drives = self.find_usb_drives()
            if self.usb_drive_path not in current_drives:
                self.destroy()
                break

    def start_usb_monitor(self):
        monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        monitor_thread.start()


if __name__ == "__main__":
    try:
        app = PasswordSafeApp()
        app.mainloop()
    except Exception as e:
        import traceback
        error_message = f"Đã xảy ra lỗi nghiêm trọng khi khởi động:\n\n{e}\n\nChi tiết:\n{traceback.format_exc()}"
        # Sử dụng messagebox của tkinter vì ttk có thể chưa khởi tạo
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Lỗi Khởi Động Nghiêm Trọng", error_message)

