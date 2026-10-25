import hashlib
import hmac
import time

MIN_FILE_SIZE = 10_000_000
CHUNK_SIZE = 1024 * 1024
HASH_ALGORITHMS = ("sha256", "sha1", "md5")

def create_hmac(message, key):
    """Tạo thẻ HMAC-SHA256 và trả về dưới dạng chuỗi hex."""
    if not isinstance(message, str) or not isinstance(key, str):
        raise TypeError("Thông điệp và khóa phải là chuỗi.")
    if not key:
        raise ValueError("Khóa HMAC không được để trống.")

    return hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac(message, key, tag):
    """Kiểm tra thẻ HMAC-SHA256 bằng hmac.compare_digest()."""
    try:
        supplied_tag = bytes.fromhex(tag)
    except (TypeError, ValueError) as error:
        raise ValueError("Thẻ HMAC phải là chuỗi hex hợp lệ.") from error

    if len(supplied_tag) != hashlib.sha256().digest_size:
        raise ValueError("Thẻ HMAC-SHA256 phải có đúng 32 byte.")

    expected_tag = bytes.fromhex(create_hmac(message, key))
    return hmac.compare_digest(expected_tag, supplied_tag)


def benchmark_file(file_obj):
    """Đo thời gian từng hàm băm trên cùng một tệp tối thiểu 10 MB."""
    file_obj.seek(0, 2)
    file_size = file_obj.tell()

    if file_size < MIN_FILE_SIZE:
        raise ValueError("Tệp đo phải có dung lượng tối thiểu 10 MB (10.000.000 byte).")

    results = {}
    for name in HASH_ALGORITHMS:
        file_obj.seek(0)
        hasher = hashlib.new(name)
        start_time = time.perf_counter()

        while True:
            chunk = file_obj.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        results[name] = {
            "digest": hasher.hexdigest(),
            "time_ms": round(elapsed_ms, 3),
        }

    file_obj.seek(0)
    return results, file_size
