import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.exceptions import InvalidSignature

ALGORITHMS = ('RSA-PSS', 'ECDSA', 'Ed25519')


def sign_bytes(private_key, message: bytes, algorithm: str) -> bytes:
    if algorithm == 'RSA-PSS':
        return private_key.sign(message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    if algorithm == 'ECDSA':
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    if algorithm == 'Ed25519':
        return private_key.sign(message)
    raise ValueError('Thuật toán chữ ký không được hỗ trợ')


def verify_bytes(public_key, message: bytes, signature: bytes, algorithm: str) -> bool:
    if algorithm not in ALGORITHMS:
        raise ValueError('Thuật toán chữ ký không được hỗ trợ')
    try:
        if algorithm == 'RSA-PSS':
            public_key.verify(signature, message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif algorithm == 'ECDSA':
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

def sign_and_verify_demo(private_key, public_key, message: bytes, algorithm: str, attacker_private_key):
    if algorithm not in ('RSA-PSS', 'ECDSA', 'Ed25519'):
        raise ValueError(f"Thuật toán {algorithm} không được hỗ trợ.")
    if not isinstance(message, bytes):
        raise TypeError("Thông điệp ký phải là bytes; hãy mã hóa văn bản bằng UTF-8.")
    results = {}
    
    start_sign = time.perf_counter()
    if algorithm == 'RSA-PSS':
        pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        signature = private_key.sign(message, pad, hashes.SHA256())
    elif algorithm == 'ECDSA':
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    elif algorithm == 'Ed25519':
        signature = private_key.sign(message)
    sign_time = (time.perf_counter() - start_sign) * 1000
    
    results['signature_size_bytes'] = len(signature)
    results['signature_hex'] = signature.hex()
    results['algorithm'] = algorithm
    results['sign_time_ms'] = sign_time

    def verify(msg, sig):
        try:
            t0 = time.perf_counter()
            if algorithm == 'RSA-PSS':
                public_key.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            elif algorithm == 'ECDSA':
                public_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            elif algorithm == 'Ed25519':
                public_key.verify(sig, msg)
            return True, (time.perf_counter() - t0) * 1000, "Xác minh thành công"
        except InvalidSignature:
            return False, 0, "LỖI: Chữ ký không khớp (Sai khóa, sai thuật toán hoặc dữ liệu/chữ ký bị sửa đổi)"
        except Exception as e:
            return False, 0, f"LỖI HỆ THỐNG: {str(e)}"

    valid, v_time, msg_ok = verify(message, signature)
    results['scenario_valid'] = {"success": valid, "verify_time_ms": v_time, "msg": msg_ok}

    tampered_message = bytearray(message)
    if tampered_message:
        tampered_message[-1] ^= 0xFF
    else:
        tampered_message.append(0x01)
    valid_tampered, _, msg_fail_tampered = verify(bytes(tampered_message), signature)
    results['scenario_tampered_content'] = {"success": valid_tampered, "msg": msg_fail_tampered}

    if algorithm == 'RSA-PSS':
        fake_signature = attacker_private_key.sign(message, pad, hashes.SHA256())
    elif algorithm == 'ECDSA':
        fake_signature = attacker_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    elif algorithm == 'Ed25519':
        fake_signature = attacker_private_key.sign(message)
        
    valid_fake_sig, _, msg_fail_fake = verify(message, fake_signature)
    results['scenario_fake_signature'] = {"success": valid_fake_sig, "msg": msg_fail_fake}

    return results
