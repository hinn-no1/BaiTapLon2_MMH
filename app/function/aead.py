"""Authenticated encryption with AES-256-GCM / ChaCha20-Poly1305 (B.2.5)."""
import json
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

ALGORITHMS = ('AES-256-GCM', 'ChaCha20-Poly1305')


def make_aad(sender: str, recipient: str, sequence: int) -> bytes:
    if not sender or not recipient or type(sequence) is not int or sequence < 0:
        raise ValueError('AAD requires sender, recipient and nonnegative sequence')
    return json.dumps({'sender': sender, 'recipient': recipient, 'sequence': sequence},
                      sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def _cipher(algorithm: str, key: bytes, nonce: bytes):
    if algorithm not in ALGORITHMS:
        raise ValueError('Unknown AEAD algorithm')
    if len(key) != 32:
        raise ValueError('AEAD requires a 32-byte key')
    if len(nonce) != 12:
        raise ValueError('AEAD demo requires a 96-bit nonce')
    if algorithm == 'AES-256-GCM':
        return AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    return ChaCha20_Poly1305.new(key=key, nonce=nonce)


def encrypt(key: bytes, plaintext: bytes, aad: bytes,
            algorithm: str = 'AES-256-GCM') -> dict:
    nonce = get_random_bytes(12)
    cipher = _cipher(algorithm, key, nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {'algorithm': algorithm, 'nonce': nonce.hex(), 'ciphertext': ciphertext.hex(),
            'tag': tag.hex(), 'aad': aad.hex()}


def decrypt(key: bytes, packet: dict) -> bytes:
    try:
        nonce = bytes.fromhex(packet['nonce'])
        ciphertext = bytes.fromhex(packet['ciphertext'])
        tag = bytes.fromhex(packet['tag'])
        aad = bytes.fromhex(packet['aad'])
        cipher = _cipher(packet['algorithm'], key, nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError('thẻ xác thực không hợp lệ') from exc


def tamper(packet: dict, field: str = 'ciphertext') -> dict:
    if field not in ('ciphertext', 'aad'):
        raise ValueError('Only ciphertext / AAD tampering supported')
    modified = packet.copy()
    raw = bytearray.fromhex(modified[field])
    if not raw:
        raise ValueError('Cannot flip a bit in an empty field')
    raw[0] ^= 0x01
    modified[field] = raw.hex()
    return modified


def roundtrip_demo(key: bytes, text: str, algorithm: str) -> dict:
    aad = make_aad('Alice', 'Bob', 1)
    packet = encrypt(key, text.encode('utf-8'), aad, algorithm)
    result = {'packet': packet, 'plaintext': decrypt(key, packet).decode('utf-8')}
    for field in ('ciphertext', 'aad'):
        try:
            decrypt(key, tamper(packet, field))
            result[field + '_tamper'] = 'LỖI: không phát hiện sửa đổi'
        except ValueError as exc:
            result[field + '_tamper'] = str(exc)
    return result
