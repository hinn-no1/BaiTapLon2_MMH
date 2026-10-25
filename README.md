# BaiTapLon2_MMH — B.2.5/B.2.6 + kiểm thử crypto

> Bản tích hợp từ ZIP dự án nhóm (25/10/2026). Các module `key_exchange.py`, `aead.py`, `mitm.py`, `mini_pki.py`, `toy_ecdsa.py`, giao diện và benchmark được bổ sung để minh họa kênh liên lạc an toàn. Demo trên cùng một Flask server **không phải** ứng dụng chat an toàn để triển khai thực tế: server nắm khóa riêng nhằm mô phỏng Alice/Bob/Eve. Không lưu/hiển thị khóa riêng qua API.

## Chạy trên Windows PowerShell

Cần Python 3.10 trở lên. Giải nén ZIP, mở PowerShell trong thư mục `BaiTapLon2_MMH-main`, chạy từng dòng:

```powershell
cd app
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Mở http://127.0.0.1:5000. Không cần kích hoạt môi trường ảo và không cần Node.js.

Linux/macOS:

```bash
cd app
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

## Thứ tự sử dụng

1. Nhập tên Alice/Bob/CA, chọn RSA-PSS, ECDSA P-256 hoặc Ed25519 rồi **Sinh khóa**. Tên phải khác nhau và khác Eve. Đổi thuật toán hoặc tên cần sinh lại khóa.
2. Nhập văn bản (1–200 ký tự) hoặc tải một tệp bất kỳ (tối đa 10 MiB). Tải thành công sẽ chọn nguồn **Tệp**; chuyển về **Văn bản** nếu muốn dùng ô thông điệp.
3. Chạy **Băm và kiểm tra HMAC** hoặc **Ký và thử xác minh**. Khóa HMAC nhập riêng. Thẻ HMAC để trống dùng thẻ vừa tạo; có thể nhập thẻ khác để kiểm tra.
4. **CA cấp chứng thư**. Kiểm tra chuỗi hợp lệ hoặc thử sửa khóa, hết hạn, sai chủ thể, thu hồi. Các tình huống lỗi dùng bản sao, không phá chứng thư thật.
5. Chọn chế độ **Có chữ ký và chứng thư** hoặc **Không xác thực**, chọn một trong hai AEAD rồi chạy kênh truyền. Chế độ có xác thực cần thực hiện bước 1 và 4 trước.
6. Xem log MITM, dấu vân tay khóa, bản xem trước bản mã/bản rõ; tải bản mã JSON hoặc bản giải mã đầy đủ. Tệp giải mã giữ nguyên byte gốc.
7. Thử DH theo p, g, a, b hoặc chạy các bài DH/ECDH/AEAD/MITM/ECDSA mẫu độc lập. Các nút thử nhanh dùng văn bản, không dùng bộ khóa hoặc tệp của kênh chính.
8. Tải bảng benchmark. Kết quả có sẵn là **số đo trên môi trường kiểm thử**, không phải số đo máy của nhóm.

## Kerberos

Kịch bản riêng giữ danh tính Alice và dịch vụ Bob; mật khẩu demo **demo123**.

| Bước | Thao tác | Kết quả đúng |
|---|---|---|
| 1 | AS cấp TGT | Chấp nhận mật khẩu đúng |
| 2 | TGS cấp vé Bob | Chấp nhận TGT và authenticator hợp lệ |
| 3 | Bob xác thực | Chấp nhận lần đầu |
| 4 | Phát lại yêu cầu cũ | Từ chối replay |
| 5 | Cùng vé, authenticator mới | Chấp nhận khi vé còn hạn |
| 6 | Thử vé hết hạn | Từ chối vé quá hạn |

Hai nút bổ sung kiểm tra timestamp cũ và replay TGS. Vé có hạn 120 giây, độ lệch timestamp tối đa 30 giây. Thử hết hạn dùng thời gian mô phỏng, không sửa đồng hồ máy. Cùng vé còn hạn được dùng lại với authenticator mới; replay chính authenticator đã chấp nhận bị chặn. Xin TGT mới không xóa cache replay của vé cũ còn hạn.

## Kiểm thử và đo lại

Chạy trong thư mục `app` (Windows):

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe benchmark_crypto.py --runs 20
```

Script xuất `benchmark_results.json` và `benchmark_results.csv`. Benchmark có 17 phép đo cho RSA-2048/RSA-3072/ECDSA-P256, ECDH/DH và hai AEAD; không đo Ed25519. ECDH bao gồm HKDF, DH-2048 đo bí mật DH thô; thời gian AEAD gồm chuyển đổi hex và chi phí Python. Dữ liệu AEAD đo có kích thước 1 MiB.

Xem `docs/TEST_STATUS.md` cho kết quả đã chạy. Báo cáo phần 3 mới nằm trong `docs/Phan_tich_thiet_ke_he_thong_va_kiem_tra_web.docx`; tài liệu Word cũ khác trong `docs` được giữ để tham khảo, không dùng thay báo cáo cập nhật.

## Cấu trúc

- `app/app.py`: Flask và các API thử nghiệm độc lập.
- `app/lab_routes.py`: các API luồng chính, upload/download, trạng thái từng phiên và Kerberos.
- `app/function/lab.py`: mini-PKI ba thuật toán, hash/HMAC, ký dữ liệu và kênh ECDH/AEAD.
- `app/function/kerberos_demo.py`: AS, TGS, Bob, vé và cache replay.
- `app/function/key_management.py`, `signatures.py`: khóa/chữ ký RSA-PSS, ECDSA và Ed25519 bằng cryptography.
- `app/function/key_exchange.py`, `aead.py`: DH/ECDH/HKDF và AEAD bằng PyCryptodome.
- `app/function/mini_pki.py`, `mitm.py`, `toy_ecdsa.py`, `hash_hmac.py`: các bài thử và hàm nền từ bản gốc.
- `app/templates/index.html`, `app/static/script.js`, `style.css`: trang thao tác.
- `app/tests_crypto.py`, `tests_regressions.py`, `tests_workflow.py`: kiểm thử tự động.

## Phạm vi mô phỏng

Các khóa riêng không trả qua API; khóa phiên chỉ hiển thị SHA-256. Riêng DH/ECDSA số nhỏ cố ý hiển thị các số bí mật để minh họa toán học. Chứng thư là JSON, không phải X.509. Kerberos tối giản có mật khẩu/salt demo cố định, không phải triển khai Kerberos V5.

Cookie chỉ chứa mã phiên ngẫu nhiên có chữ ký; dữ liệu và khóa nằm trong bộ nhớ server. Các phiên trình duyệt được tách biệt, hết hạn sau 30 phút không hoạt động; tối đa 32 phiên. Khởi động lại server làm mất trạng thái. Mọi vai trò cùng một tiến trình, không phải ứng dụng chat an toàn hay dịch vụ CA/KDC sản xuất. Chống replay có trạng thái áp dụng cho Kerberos; kênh DH không triển khai giao thức chống phát lại nhiều thông điệp.
