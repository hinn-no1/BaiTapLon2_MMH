# BaiTapLon2_MMH — B.2.5/B.2.6 + kiểm thử crypto

> Bản tích hợp từ ZIP dự án nhóm (25/10/2026). Các module `key_exchange.py`, `aead.py`, `mitm.py`, `mini_pki.py`, `toy_ecdsa.py`, giao diện và benchmark được bổ sung để minh họa kênh liên lạc an toàn. Demo trên cùng một Flask server **không phải** ứng dụng chat an toàn để triển khai thực tế: server nắm khóa riêng nhằm mô phỏng Alice/Bob/Eve. Không lưu/hiển thị khóa riêng qua API.

## Khởi chạy

```bash
cd app
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/WSL: source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Truy cập <http://127.0.0.1:5000>.

## Các màn hình/API

| API | Công dụng |
| --- | --- |
| `GET /api/toy-dh` | DH p=23,g=5 (A=8,B=19,K=2) và log MITM số nhỏ xác định |
| `GET /api/ecdh` | ECDH P-256 khóa tạm + HKDF-SHA256 (32 byte); chỉ hiển thị SHA-256 khóa phiên |
| `POST /api/aead` | HKDF + AES-256-GCM hoặc ChaCha20-Poly1305; sửa 1 bit bản mã/AAD phải bị từ chối |
| `POST /api/mitm` | Hai chế độ: không xác thực (Eve đọc được) / có CA+ECDSA+chứng thư (Eve bị chặn) |
| `GET /api/toy-ecdsa` | Tự cài ECDSA E17(3,5), khớp đúng vector đề bài |
| `GET /api/benchmarks` | Hiển thị `app/benchmark_results.json` sau khi chạy benchmark |

Ví dụ gọi API:

```bash
curl -X POST http://127.0.0.1:5000/api/mitm \
  -H 'Content-Type: application/json' \
  -d '{"message":"Xin chao Bob!","algorithm":"AES-256-GCM"}'
```

## Kiểm thử (nên thực hiện trước khi nhóm ghép code)

```bash
cd app
python -m unittest -v tests_crypto
python function/toy_ecdsa.py
python benchmark_crypto.py --runs 20
```

Benchmark lưu `benchmark_results.json` và `.csv` trong thư mục `app`. Chạy đủ **20 lần cho mỗi thao tác**; các thời gian đo dùng `perf_counter_ns()` và công bố theo ms. Thao tác sinh RSA-3072 có thể chiếm nhiều thời gian; không giảm số lần chạy khi làm bài chính thức. CPU, phiên bản Python/PyCryptodome và thống kê được ghi trong kết quả; kết quả đo trên máy khác không thể dùng thay thế số đo của nhóm.

### Chốt kiểm thử crypto

- DH số nhỏ: Alice A=8, Bob B=19, K_A=K_B=2.
- DH số nhỏ khi MITM: Eve thay khóa hai phía, thu K_AE=1 và K_EB=15 (không trùng nhau).
- ECDH: hai phía dẫn xuất cùng khóa 256 bit qua HKDF cùng salt/context.
- AEAD: giải mã đúng khi tag hợp lệ; sửa 1 bit ciphertext hoặc AAD thì từ chối, không trả plaintext.
- MITM không xác thực: Eve giải mã thông điệp rồi mã hóa lại cho Bob (2 khóa phiên khác nhau).
- MITM có CA + chữ ký: thay public key tạm không khớp chữ ký Alice; chứng thư Eve dù hợp lệ cũng không có subject Alice.
- Certificate: bốn lỗi cần phát hiện (sai chữ ký CA, hết hạn, sai subject, CRL).
- Toy ECDSA: Q=(12,16), (r,s)=(16,6), X=(16,1); đổi h thì xác minh thất bại.
- Tránh dùng lại cặp `(key, nonce)` cho GCM/ChaCha20, không dùng ECB; hash MD5/SHA-1 chỉ dùng so sánh.

## Cấu trúc chính

```text
app/
  app.py                  # Flask API và UI
  function/
    key_exchange.py        # toy DH, ECDH+HKDF, DH-2048
    aead.py                # AES-GCM/ChaCha20-Poly1305 + sửa bit
    mini_pki.py            # CA ký và xác minh chứng thư JSON
    mitm.py                # 2 chế độ MITM và log
    toy_ecdsa.py           # toán học điểm EC tự cài, CHỈ cho đường cong nhỏ
    hash_hmac.py           # code nhóm; được thêm imports/constants thiếu
  benchmark_crypto.py     # RSA/ECDSA, DH/ECDH, AEAD; xuất CSV/JSON
  tests_crypto.py         # unittest
  templates/index.html
  static/style.css
  static/script.js
  requirements.txt
```

## Giới hạn mô phỏng và hướng ghép nhánh

- Demo cấp CA và danh tính mới mỗi request, không cấp CA cho hệ thống thật; khóa CA tin cậy được ghim cục bộ. Đối với ứng dụng thật nên dùng giao thức như TLS 1.3 thay vì tự chế giao thức.
- Chưa làm UI quản lý chứng thư cho đầy đủ B.2.4, cũng chưa làm UI sinh/hiển thị khóa cho toàn B.2.1; nhóm có thể tái sử dụng `mini_pki.py` và các API hiện có để tích hợp module riêng.
- Module `hash_hmac.py` của nhóm ban đầu thiếu `import hashlib, hmac, time` và hằng số `MIN_FILE_SIZE, CHUNK_SIZE, HASH_ALGORITHMS` — bản này đã bổ sung để tránh `NameError`. Chức năng phần B.2.2 đầy đủ cần kiểm tra riêng với các yêu cầu file/text/avalanche.
- Chưa có số benchmark chính thức của backend dự án: **không bịa kết quả**. Tự chạy script tại máy đo rồi lấy CSV làm bảng báo cáo.

Nguồn yêu cầu: `bài tập lớn 2_NMMM.docx` (mục B.2.5–B.2.7, B.8 và B.9). Nguồn tham khảo kỹ thuật: [PyCryptodome ECDH](https://www.pycryptodome.org/src/protocol/dh), [HKDF](https://www.pycryptodome.org/src/protocol/kdf), [ECDSA](https://www.pycryptodome.org/src/signature/dsa), RFC 3526 (DH group 14), RFC 5869 (HKDF), NIST SP 800-38D (GCM).


## Tài liệu báo cáo thống nhất định dạng

Tệp Word hoàn thiện: `docs/Bao_cao_B25_B26_C1_C3_ECDSA_Hoan_chinh.docx` (Heading 2, Times New Roman 13 đậm; nội dung Times New Roman 12, viết liền mạch). Bảng đo tham khảo trong Word **không thay** bảng đo PyCryptodome trên máy nhóm. Xem `docs/TEST_STATUS.md` để đối chiếu các test đã chạy và chưa thể chạy.
