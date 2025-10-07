# BÁO CÁO DỰ ÁN GIỮA KỲ - ỨNG DỤNG KÉT SẮT MẬT KHẨU (PASSWORD SAFE)
## 1. Thông Tin Sinh Viên
Họ và Tên: Vương Huy Huy

Mã Số Sinh Viên: 23010714


## 2. Giới Thiệu Dự Án
Password Safe là một ứng dụng desktop được phát triển bằng Python, với mục tiêu cung cấp một giải pháp an toàn và tiện lợi để lưu trữ, quản lý các thông tin nhạy cảm như mật khẩu, ghi chú cá nhân. Lấy cảm hứng từ ý tưởng về một chiếc "két sắt số", ứng dụng cho phép người dùng mã hóa toàn bộ dữ liệu của mình bằng các thuật toán mạnh mẽ và lưu trữ chúng một cách an toàn trên máy tính hoặc thiết bị di động như USB.

Điểm nhấn của dự án là sự kết hợp giữa bảo mật cấp cao (thuật toán AES) và tính di động, cho phép người dùng mang theo dữ liệu của mình một cách an toàn và truy cập trên bất kỳ máy tính nào có cài đặt môi trường Python.

## 3. Các Tính Năng Nổi Bật
Ứng dụng được trang bị đầy đủ các chức năng từ cơ bản đến nâng cao, đáp ứng nhu cầu quản lý mật khẩu an toàn:

Giao Diện Hiện Đại: Sử dụng thư viện ttkbootstrap để tạo ra một giao diện người dùng (GUI) chuyên nghiệp, đẹp mắt với chủ đề tối (dark mode).

Mã Hóa Mạnh Mẽ (AES): Dữ liệu được bảo vệ bằng thuật toán mã hóa đối xứng AES, tiêu chuẩn vàng trong ngành bảo mật, đảm bảo chỉ người có mật khẩu chủ mới có thể truy cập.

Tùy Chọn Mã Hóa Cổ Điển (Tham Khảo):

Cung cấp thêm 4 thuật toán mã hóa cổ điển là Caesar (dịch vòng), Transposition (hoán vị), Affine, và Hill cho mục đích học tập và so sánh.

Người dùng có thể tự nhập khóa (key) tùy chỉnh cho 2 thuật toán này để hiểu rõ hơn về cơ chế hoạt động.

Yêu cầu khóa có cấu trúc: Đối với các thuật toán phức tạp hơn như Affine và Hill, ứng dụng hướng dẫn người dùng nhập khóa theo đúng định dạng (ví dụ: a,b cho Affine và a,b,c,d cho ma trận Hill 2x2), giúp sinh viên hiểu rõ hơn về cấu trúc khóa của từng loại mã hóa.

Ứng dụng luôn hiển thị cảnh báo về độ an toàn thấp của 2 thuật toán này.

Trình Tạo Mật Khẩu An Toàn: Tích hợp công cụ tạo mật khẩu ngẫu nhiên, mạnh mẽ với các tùy chọn tùy chỉnh về độ dài, loại ký tự (chữ hoa, chữ thường, số, ký tự đặc biệt).

Chế Độ Xem Song Song: Cho phép người dùng xem đồng thời "bản rõ" (dữ liệu gốc) và "bản mã hóa" (dữ liệu sau khi được mã hóa), giúp trực quan hóa quá trình bảo mật.

Chế Độ Di Động (USB Portable):

Xuất dữ liệu ra USB: Chỉ với một cú nhấp chuột, ứng dụng sẽ mã hóa dữ liệu và tạo một gói di động trên USB, bao gồm file dữ liệu .psafe và file khởi động start_app.bat.

Tự động đóng khi rút USB: Để đảm bảo an toàn, ứng dụng sẽ tự động đóng ngay lập tức khi phát hiện USB đã được rút ra khỏi máy tính.

Quản Lý File Linh Hoạt:

Hỗ trợ nhập dữ liệu nhanh từ các file văn bản thô (.txt).

Lưu và mở các file dữ liệu đã được mã hóa (.psafe).

## 4. Công Nghệ Sử Dụng
Ngôn ngữ lập trình: Python 3

Thư viện giao diện: Tkinter, ttkbootstrap

Thư viện mã hóa: cryptography (cho AES)

Thư viện hệ thống: psutil (để nhận diện và giám sát USB)

Các thư viện chuẩn khác: os, threading, random, string, base64.

## 5. Hướng Dẫn Cài Đặt và Sử Dụng
a. Yêu cầu
Đã cài đặt Python 3.7 trở lên trên máy tính.

b. Các bước cài đặt
Clone hoặc tải về mã nguồn:

Tải toàn bộ các file của dự án (main_app.py, crypto_utils.py, requirements.txt) vào cùng một thư mục.

Cài đặt các thư viện cần thiết:

Mở cửa sổ dòng lệnh (Command Prompt hoặc PowerShell) trong thư mục chứa mã nguồn.

Chạy lệnh sau để cài đặt tất cả các thư viện phụ thuộc:

pip install -r requirements.txt

c. Cách chạy ứng dụng
Sau khi cài đặt thành công, chạy lệnh sau trong cửa sổ dòng lệnh:

python main_app.py

Cửa sổ ứng dụng sẽ hiện ra và sẵn sàng để sử dụng.

## 6. Kịch bản sử dụng cơ bản
Nhập dữ liệu: Soạn thảo mật khẩu trực tiếp hoặc nhấn "Nhập từ .txt" để tải dữ liệu từ file.

Tạo mật khẩu mạnh: Sử dụng chức năng "Tạo Mật Khẩu" để tạo và chèn một mật khẩu an toàn mới.

Xem trước mã hóa: Chọn thuật toán mong muốn và nhấn "Xem Mã Hóa" để xem dữ liệu sẽ trông như thế nào sau khi được bảo vệ.

Lưu file an toàn: Nhấn "Lưu & Mã Hóa", đặt tên file và nhập mật khẩu chủ để lưu file .psafe trên máy tính.

Tạo phiên bản USB di động: Cắm USB, nhấn "Xuất Ra USB", sau đó làm theo hướng dẫn để chép các file cần thiết vào USB.
