@echo off
REM File này dùng để khởi động ứng dụng Password Safe từ USB.
REM Đảm bảo bạn đã chép các file main_app.py và crypto_utils.py vào cùng thư mục trên USB.

echo Starting Password Safe...
REM Lệnh "python" yêu cầu máy tính phải được cài đặt Python và đã thêm vào biến môi trường PATH.
python main_app.py

REM Giữ cửa sổ terminal mở sau khi ứng dụng đóng để xem thông báo (nếu có).
pause
