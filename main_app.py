import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
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
        super().__init__(themename="superhero")
        
        self.title("Password Safe - Két Sắt Mật Khẩu")
        self.geometry("1100x700")
        self.center_window()

        self.current_file_path = None
        self.usb_drive_path = None
        
        self.create_widgets()

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(expand=True, fill=BOTH)

        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=X, pady=(0, 15))

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
        
        algo_frame = ttk.Labelframe(main_frame, text=" Thuật Toán Mã Hóa ", padding=15)
        algo_frame.pack(fill=X, pady=(0, 15))
        
        self.algo_var = tk.StringVar(value="AES")
        self.algorithms = ["AES", "Caesar", "Transposition", "Affine", "Hill"]
        
        algo_label = ttk.Label(algo_frame, text="Chọn thuật toán:")
        algo_label.pack(side=LEFT, padx=(0, 10))
        
        algo_menu = ttk.Combobox(
            algo_frame, textvariable=self.algo_var, values=self.algorithms,
            state="readonly", bootstyle="info"
        )
        algo_menu.pack(side=LEFT, fill=X, expand=True)
        algo_menu.bind("<<ComboboxSelected>>", self.on_algo_change)
        
        self.algo_warning_label = ttk.Label(algo_frame, text="", bootstyle="warning")
        self.algo_warning_label.pack(side=LEFT, padx=(10, 0))
        self.on_algo_change()

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill=BOTH)
        tab_plain = ttk.Frame(notebook, padding=0)
        self.text_area = tk.Text(
            tab_plain, wrap="word", bg="#2b3e50", fg="#ffffff",
            insertbackground="#ffffff", undo=True, font=("Segoe UI", 12),
            bd=0, highlightthickness=0, padx=10, pady=10,
        )
        self.text_area.pack(expand=True, fill=BOTH)
        notebook.add(tab_plain, text="Soạn Thảo (Bản Rõ)")
        tab_encrypted = ttk.Frame(notebook, padding=0)
        self.encrypted_text_area = tk.Text(
            tab_encrypted, wrap="word", bg="#202020", fg="#a0a0a0",
            insertbackground="#ffffff", font=("Courier New", 12),
            bd=0, highlightthickness=0, padx=10, pady=10, state="disabled"
        )
        self.encrypted_text_area.pack(expand=True, fill=BOTH)
        notebook.add(tab_encrypted, text="Xem Trước (Bản Mã Hóa)")
        self.notebook = notebook
        self.status_bar = ttk.Label(self, text="Sẵn sàng", padding=5, bootstyle="primary-inverse", anchor=W)
        self.status_bar.pack(side=BOTTOM, fill=X)

    def on_algo_change(self, event=None):
        algo = self.algo_var.get()
        if algo != "AES":
            self.algo_warning_label.config(text="⚠️ KHÔNG AN TOÀN")
        else:
            self.algo_warning_label.config(text="")

    def _perform_encryption_flow(self):
        content = self.text_area.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Nội dung rỗng", "Không có gì để mã hóa.", parent=self)
            return None, None

        key_or_pass = self.prompt_for_key_or_password()
        if not key_or_pass:
            return None, None
        
        selected_algorithm = self.algo_var.get().upper()
        if selected_algorithm != "AES":
             if not messagebox.askokcancel("Cảnh Báo Bảo Mật", f"Bạn đang sử dụng thuật toán '{selected_algorithm}' KHÔNG AN TOÀN. Chỉ nên dùng cho mục đích thử nghiệm. Bạn có muốn tiếp tục?", parent=self):
                return None, None
            
        encrypted_blob = crypto_utils.encrypt_data(key_or_pass, content, selected_algorithm)
        if not encrypted_blob:
            messagebox.showerror("Lỗi Mã Hóa", "Quá trình mã hóa đã thất bại. Vui lòng kiểm tra lại định dạng khóa.", parent=self)
            return None, None
        
        return encrypted_blob, key_or_pass

    def update_encrypted_view(self, content_bytes):
        self.encrypted_text_area.config(state="normal")
        self.encrypted_text_area.delete(1.0, tk.END)
        encoded_content = base64.b64encode(content_bytes).decode('utf-8')
        self.encrypted_text_area.insert(tk.END, encoded_content)
        self.encrypted_text_area.config(state="disabled")

    def preview_encryption(self):
        encrypted_blob, _ = self._perform_encryption_flow()
        if encrypted_blob:
            self.update_encrypted_view(encrypted_blob)
            self.status_bar.config(text=f"Đã xem trước mã hóa với thuật toán {self.algo_var.get()}.")
            self.notebook.select(1)

    def clear_clipboard_if_unchanged(self, original_password):
        try:
            if self.clipboard_get() == original_password:
                self.clipboard_clear()
                self.status_bar.config(text="Clipboard đã được xóa an toàn.")
        except tk.TclError:
            pass

    def open_password_generator(self):
        gen_window = ttk.Toplevel(self)
        gen_window.title("Trình Tạo Mật Khẩu")
        gen_window.geometry("600x450")
        gen_window.transient(self)
        gen_window.grab_set()
        
        length_var = tk.IntVar(value=16)
        use_upper_var = tk.BooleanVar(value=True)
        use_lower_var = tk.BooleanVar(value=True)
        use_digits_var = tk.BooleanVar(value=True)
        use_symbols_var = tk.BooleanVar(value=True)
        password_var = tk.StringVar()

        def copy_to_clipboard():
            password = password_var.get()
            if not password: return
            self.clipboard_clear()
            self.clipboard_append(password)
            self.status_bar.config(text="Đã sao chép! Clipboard sẽ được xóa sau 45 giây.")
            threading.Timer(45.0, self.clear_clipboard_if_unchanged, [password]).start()

        def update_length_label(val): length_label.config(text=f"Độ dài mật khẩu: {int(float(val))}")
        def generate_password():
            length, char_pool = length_var.get(), ""
            if use_upper_var.get(): char_pool += string.ascii_uppercase
            if use_lower_var.get(): char_pool += string.ascii_lowercase
            if use_digits_var.get(): char_pool += string.digits
            if use_symbols_var.get(): char_pool += string.punctuation
            if not char_pool:
                messagebox.showwarning("Lỗi", "Vui lòng chọn ít nhất một loại ký tự.", parent=gen_window); return
            password_var.set("".join(random.choices(char_pool, k=length)))
        def insert_password():
            self.text_area.insert(tk.END, password_var.get() + "\n"); gen_window.destroy()
        
        gen_frame = ttk.Frame(gen_window, padding=20)
        gen_frame.pack(expand=True, fill=BOTH)
        result_frame = ttk.Frame(gen_frame)
        result_frame.pack(fill=X, pady=(0, 15))
        password_entry = ttk.Entry(result_frame, textvariable=password_var, font=("Courier New", 12), bootstyle="success", state="readonly")
        password_entry.pack(side=LEFT, expand=True, fill=X, ipady=5)
        copy_button = ttk.Button(result_frame, text="Sao chép", command=copy_to_clipboard, bootstyle="secondary")
        copy_button.pack(side=LEFT, padx=(10, 0))
        options_frame = ttk.Labelframe(gen_frame, text=" Tùy chọn ", padding=15)
        options_frame.pack(fill=X, pady=(0, 15))
        length_label = ttk.Label(options_frame, text=f"Độ dài mật khẩu: {length_var.get()}")
        length_label.pack(anchor=W)
        length_slider = ttk.Scale(options_frame, from_=8, to=64, variable=length_var, command=update_length_label)
        length_slider.pack(fill=X, pady=(5, 15))
        upper_check = ttk.Checkbutton(options_frame, text="Bao gồm chữ hoa (A-Z)", variable=use_upper_var, bootstyle="primary-round-toggle")
        upper_check.pack(anchor=W, pady=2)
        lower_check = ttk.Checkbutton(options_frame, text="Bao gồm chữ thường (a-z)", variable=use_lower_var, bootstyle="primary-round-toggle")
        lower_check.pack(anchor=W, pady=2)
        digits_check = ttk.Checkbutton(options_frame, text="Bao gồm số (0-9)", variable=use_digits_var, bootstyle="primary-round-toggle")
        digits_check.pack(anchor=W, pady=2)
        symbols_check = ttk.Checkbutton(options_frame, text="Bao gồm ký tự đặc biệt (!@#$%)", variable=use_symbols_var, bootstyle="primary-round-toggle")
        symbols_check.pack(anchor=W, pady=2)
        action_frame = ttk.Frame(gen_frame)
        action_frame.pack(fill=X, pady=(10, 0))
        generate_button = ttk.Button(action_frame, text="Tạo mới", command=generate_password, bootstyle="info")
        generate_button.pack(side=LEFT, expand=True, fill=X, padx=(0, 5))
        insert_button = ttk.Button(action_frame, text="Chèn vào", command=insert_password, bootstyle="success")
        insert_button.pack(side=LEFT, expand=True, fill=X, padx=(5, 0))
        generate_password()

    def import_from_txt(self):
        if self.text_area.get(1.0, tk.END).strip():
            if not messagebox.askyesno("Cảnh Báo", "Thao tác này sẽ xóa nội dung hiện tại. Bạn có muốn tiếp tục?"):
                return
        filepath = filedialog.askopenfilename(title="Chọn file .txt để nhập", filetypes=[("Text Files", "*.txt"), ("All files", "*.*")])
        if not filepath: return
        try:
            with open(filepath, 'r', encoding='utf-8') as f: content = f.read()
            self.text_area.delete(1.0, tk.END); self.text_area.insert(tk.END, content)
            self.encrypted_text_area.config(state="normal"); self.encrypted_text_area.delete(1.0, tk.END); self.encrypted_text_area.config(state="disabled")
            self.current_file_path = None 
            self.status_bar.config(text=f"Đã nhập nội dung từ: {os.path.basename(filepath)}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể đọc file .txt: {e}")

    def prompt_for_key_or_password(self):
        algo = self.algo_var.get().upper()
        prompts = {
            "AES": ("Nhập Mật Khẩu Chủ", "Vui lòng nhập mật khẩu chủ của bạn:"),
            "CAESAR": ("Nhập Khóa Dịch Chuyển", "Nhập khóa là một số nguyên (ví dụ: 3):"),
            "TRANSPOSITION": ("Nhập Khóa Hoán Vị", "Nhập khóa là một chuỗi chữ cái không lặp lại (ví dụ: 'PYTHON'):"),
            "AFFINE": ("Nhập Khóa Affine", "Nhập khóa dạng a,b (ví dụ: 5,8).\n'a' phải nguyên tố cùng nhau với 26."),
            "HILL": ("Nhập Khóa Hill (2x2)", "Nhập 4 số cho ma trận [[a,b],[c,d]] dạng a,b,c,d\n(ví dụ: 9,4,5,7).")
        }
        title, prompt = prompts.get(algo, ("Lỗi", "Thuật toán không xác định"))
        show_char = '*' if algo == "AES" else ''
        return simpledialog.askstring(title, prompt, show=show_char, parent=self)

    def open_encrypted_file(self):
        filepath = filedialog.askopenfilename(title="Chọn file để giải mã", filetypes=[("Password Safe Files", "*.psafe"), ("All files", "*.*")])
        if not filepath: return
        try:
            with open(filepath, 'rb') as f: file_content = f.read()
            if not file_content: messagebox.showerror("Lỗi", "File rỗng.", parent=self); return
            algo_id_map = {1: "AES", 2: "Caesar", 3: "Transposition", 4: "Affine", 5: "Hill"}
            self.algo_var.set(algo_id_map.get(file_content[0], "AES"))
            self.on_algo_change()
        except Exception as e:
            messagebox.showerror("Lỗi Đọc File", f"Không thể đọc file: {e}", parent=self); return

        key_or_pass = self.prompt_for_key_or_password()
        if not key_or_pass: return
        
        decrypted_content = crypto_utils.decrypt_data(key_or_pass, file_content)
        if decrypted_content is not None:
            self.text_area.delete(1.0, tk.END); self.text_area.insert(tk.END, decrypted_content)
            self.update_encrypted_view(file_content)
            self.current_file_path, self.notebook.select(0)
            self.status_bar.config(text=f"Đã mở và giải mã thành công: {os.path.basename(filepath)}")
        else:
            messagebox.showerror("Lỗi Giải Mã", "Mật khẩu/khóa không đúng hoặc file đã bị hỏng.", parent=self)

    def save_encrypted_file(self):
        filepath = filedialog.asksaveasfilename(title="Lưu file mã hóa", defaultextension=".psafe", filetypes=[("Password Safe Files", "*.psafe"), ("All files", "*.*")])
        if not filepath: return
        if os.path.exists(filepath):
            if not messagebox.askyesno("Cảnh Báo", f"File '{os.path.basename(filepath)}' đã tồn tại. Ghi đè?", parent=self): return
        
        encrypted_blob, key_or_pass = self._perform_encryption_flow()
        if encrypted_blob and key_or_pass:
            is_new_file = not self.current_file_path or os.path.normpath(self.current_file_path) != os.path.normpath(filepath)
            if is_new_file and self.algo_var.get() == "AES":
                confirm_pass = simpledialog.askstring("Xác Nhận Mật Khẩu", "Nhập lại mật khẩu để xác nhận:", show='*', parent=self)
                if key_or_pass != confirm_pass:
                    messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp.", parent=self); return

            try:
                with open(filepath, 'wb') as f: f.write(encrypted_blob)
                self.current_file_path = filepath
                self.update_encrypted_view(encrypted_blob)
                self.status_bar.config(text=f"Đã mã hóa ({self.algo_var.get()}) và lưu thành công: {os.path.basename(filepath)}")
                messagebox.showinfo("Thành Công", "Dữ liệu đã được mã hóa và lưu an toàn!", parent=self)
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể ghi file: {e}", parent=self)
    
    def find_usb_drives(self):
        return [p.mountpoint for p in psutil.disk_partitions() if 'removable' in p.opts and 'disk' in p.fstype]

    def export_to_usb(self):
        usb_drives, usb_path = self.find_usb_drives(), None
        if not usb_drives:
            messagebox.showerror("Không Tìm Thấy USB", "Vui lòng cắm USB và thử lại.", parent=self); return
        elif len(usb_drives) > 1:
            choice_win = ttk.Toplevel(self)
            choice_win.title("Chọn Ổ Đĩa USB"); choice_win.geometry("300x200"); choice_win.transient(self); choice_win.grab_set()
            ttk.Label(choice_win, text="Tìm thấy nhiều ổ USB. Vui lòng chọn một:").pack(pady=10)
            usb_var = tk.StringVar()
            for drive in usb_drives: ttk.Radiobutton(choice_win, text=drive, variable=usb_var, value=drive).pack(anchor=W, padx=20)
            def on_select(): nonlocal usb_path; usb_path = usb_var.get(); choice_win.destroy()
            ttk.Button(choice_win, text="Xác nhận", command=on_select, bootstyle="success").pack(pady=10)
            self.wait_window(choice_win)
        else: usb_path = usb_drives[0]
        if not usb_path: return
        
        encrypted_blob, _ = self._perform_encryption_flow()
        if encrypted_blob:
            try:
                with open(os.path.join(usb_path, "passwords.psafe"), 'wb') as f: f.write(encrypted_blob)
                bat_content = f"@echo off\nrem Dam bao ban da chep cac file main_app.py va crypto_utils.py vao cung thu muc\npython main_app.py\npause\n"
                with open(os.path.join(usb_path, "start_app.bat"), 'w') as f: f.write(bat_content)
                self.usb_drive_path = usb_path
                messagebox.showinfo("Thành Công!", f"Đã xuất dữ liệu thành công ra USB ({usb_path}).", parent=self)
                self.start_usb_monitor()
            except Exception as e:
                messagebox.showerror("Lỗi Ghi File", f"Không thể lưu file vào USB: {e}", parent=self)
            
    def monitor_usb(self):
        if not self.usb_drive_path: return
        while True:
            time.sleep(3)
            if self.usb_drive_path not in self.find_usb_drives(): self.destroy(); break

    def start_usb_monitor(self):
        monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True); monitor_thread.start()

if __name__ == "__main__":
    try:
        app = PasswordSafeApp()
        app.mainloop()
    except Exception as e:
        import traceback
        error_message = f"Đã xảy ra lỗi nghiêm trọng khi khởi động:\n\n{e}\n\nChi tiết:\n{traceback.format_exc()}"
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Lỗi Khởi Động Nghiêm Trọng", error_message)