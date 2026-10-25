# Trạng thái kiểm thử – BTL2 (25/10/2026)

Bộ mã nguồn và báo cáo đã hoàn thiện phần B.2.5, B.2.6, C1, C3 và toy ECDSA về mặt cài đặt/tài liệu. Phân biệt **đã chạy** với **cần chạy tại máy nhóm**.

## Đã chạy được trong môi trường biên soạn

`cd app && python -m unittest -v tests_crypto`: 10 bài kiểm thử, **5 PASS**, **5 SKIPPED** vì Python hiện tại chưa có PyCryptodome. Cụ thể 5 PASS kiểm tra ECDSA số nhỏ, tính hợp lệ phép toán điểm, HMAC-SHA256, SHA256 mẫu và kích thước file tối thiểu; 5 SKIPPED gồm DH/ECDH tích hợp, AEAD, MITM và các trường hợp sai chứng thư. `python -m compileall -q .` không phát hiện lỗi cú pháp. Vector DH được tính độc lập: A=8, B=19, K=2; log MITM số nhỏ: K_AE=1 và K_EB=15. Vector ECDSA cho Q=(12,16), chữ ký (16,6), X=(16,1) đã xác minh.

Thư viện `cryptography` được dùng để đo tham khảo trên môi trường Linux; các số này KHÔNG là số đo chính thức của dự án PyCryptodome. Dữ liệu tham khảo lưu tại `benchmark_tham_khao_cryptography.json` và `benchmark_tham_khao_chu_ky.json`; có script tương ứng để kiểm chứng.

## Bắt buộc chạy trước khi nộp

Tại thư mục `app` chạy `python -m pip install -r requirements.txt`, `python -m unittest -v tests_crypto`, `python app.py`, mở `http://127.0.0.1:5000` và kiểm tra chức năng cả hai chế độ MITM trên cả hai AEAD. Cuối cùng chạy `python benchmark_crypto.py --runs 20`, thay các bảng tham khảo trong Word bằng `app/benchmark_results.csv`. Lưu ảnh minh chứng để đáp ứng B.10. Chỉ tuyên bố hoàn thành thực nghiệm khi toàn bộ 10 test thực thi không có SKIP hay FAILED.

## Phạm vi bàn giao

Bản này tập trung phần được phân công B.2.5, B.2.6, C1, C3, benchmark B.2.7 và mở rộng toy ECDSA. Các UI/API của B.2.1, B.2.2, B.2.3, B.2.4 thuộc phần phối hợp nhóm, chưa được thực hiện đầy đủ trong dự án này; phần `mini_pki.py` hỗ trợ MITM nhưng không thay toàn bộ giao diện mini-PKI. Demo tập trung mô phỏng trong cùng backend, không dùng như một kênh chat an toàn khi vận hành thực tế.
