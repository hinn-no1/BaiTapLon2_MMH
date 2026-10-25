from __future__ import annotations
import hashlib
import secrets
from Crypto.PublicKey import ECC
from .key_exchange import create_ecdh_party, ecdh_session_key, public_key_pem
from .aead import encrypt, decrypt, make_aad
from .mini_pki import make_demo_pki, signed_data, check_signature, verify_certificate


def key_fingerprint(key: bytes) -> str:
    """Display SHA-256(key), NEVER the shared raw secret or the session key itself."""
    return hashlib.sha256(key).hexdigest()


def unauthenticated_mitm(message: str, algorithm: str = 'AES-256-GCM') -> dict:
    logs = []
    alice, bob = create_ecdh_party(), create_ecdh_party()
    eve_to_alice, eve_to_bob = create_ecdh_party(), create_ecdh_party()
    salt_ae, salt_eb = secrets.token_bytes(32), secrets.token_bytes(32)
    context = b'BTL2-MITM-v1'
    logs.append('1. Alice gửi A=aG, Eve chặn và gửi E1=e1G cho Bob.')
    logs.append('2. Bob gửi B=bG, Eve chặn và gửi E2=e2G cho Alice.')
    ka = ecdh_session_key(alice, eve_to_alice.public_key(), salt_ae, context)
    ke_a = ecdh_session_key(eve_to_alice, alice.public_key(), salt_ae, context)
    kb = ecdh_session_key(bob, eve_to_bob.public_key(), salt_eb, context)
    ke_b = ecdh_session_key(eve_to_bob, bob.public_key(), salt_eb, context)
    assert ka == ke_a and ke_b == kb and ka != kb
    logs.append('3. Alice và Eve thiết lập K_AE; Eve và Bob thiết lập K_EB.')
    logs.append('4. K_AE != K_EB: Eve có cả hai khóa vì đã thay public key.')
    aad = make_aad('Alice', 'Bob', 1)
    from_alice = encrypt(ka, message.encode('utf-8'), aad, algorithm)
    seen_by_eve = decrypt(ke_a, from_alice).decode('utf-8')
    logs.append('5. Eve giải mã thông điệp của Alice: ' + repr(seen_by_eve))
    to_bob = encrypt(ke_b, seen_by_eve.encode('utf-8'), aad, algorithm)
    seen_by_bob = decrypt(kb, to_bob).decode('utf-8')
    logs.append('6. Eve mã hóa lại bằng K_EB; Bob giải mã thành công, không biết có MITM.')
    return {
        'mode': 'DH không xác thực', 'mitm_success': True,
        'alice_eve_key_sha256': key_fingerprint(ka),
        'eve_bob_key_sha256': key_fingerprint(kb),
        'keys_different': ka != kb, 'eve_read': seen_by_eve,
        'bob_received': seen_by_bob, 'alice_to_eve_packet': from_alice,
        'eve_to_bob_packet': to_bob, 'log': logs,
    }


def auth_transcript(*, session_id: str, sender: str, recipient: str,
                    ephemeral_pem: str) -> dict:
    return {'session_id': session_id, 'sender': sender, 'recipient': recipient,
            'ephemeral_public_key': ephemeral_pem}


def authenticated_mitm(message: str, algorithm: str = 'AES-256-GCM') -> dict:
    logs = []
    pki = make_demo_pki()
    ca_public = pki['ca_private'].public_key()  # pinned, trusted CA public key
    alice_eph, bob_eph, eve_eph = (create_ecdh_party() for _ in range(3))
    session_id = secrets.token_hex(16)
    transcript = auth_transcript(session_id=session_id, sender='Alice', recipient='Bob',
                                 ephemeral_pem=public_key_pem(alice_eph))
    alice_sig = signed_data(pki['alice_private'], transcript)
    logs.append('1. Alice ký bản ghi (session_id, Alice, Bob, A=aG) bằng khóa ECDSA dài hạn.')
    logs.append('2. Alice gửi A, chữ ký và chứng thư Alice do CA ký.')
    alice_identity = verify_certificate(pki['alice_cert'],
                                        ca_public=ca_public, expected_subject='Alice')
    logs.append('3. Bob xác minh CA → chứng thư Alice: HỢP LỆ, subject = Alice.')

    # Attack #1: replace Alice ephemeral key, reuse Alice's original signature.
    forged = dict(transcript, ephemeral_public_key=public_key_pem(eve_eph))
    substituted_signature_ok = check_signature(alice_identity, forged, alice_sig)
    assert not substituted_signature_ok
    logs.append('4. Eve thay A bằng E=eG nhưng giữ chữ ký Alice: KHÔNG HỢP LỆ.')

    # Attack #2: Eve signs with their own valid certificate, still not Alice.
    eve_subject_rejected = False
    try:
        verify_certificate(pki['eve_cert'], ca_public=ca_public, expected_subject='Alice')
    except ValueError as exc:
        eve_subject_rejected = True
        logs.append('5. Eve đưa chứng thư thật của Eve: BỊ CHẶN (' + str(exc) + ').')
    assert eve_subject_rejected
    # Untampered Alice transcript verifies and can establish a secure authenticated channel.
    original_signature_ok = check_signature(alice_identity, transcript, alice_sig)
    assert original_signature_ok
    bob_identity = verify_certificate(pki['bob_cert'], ca_public=ca_public,
                                      expected_subject='Bob')
    bob_transcript = auth_transcript(session_id=session_id, sender='Bob', recipient='Alice',
                                    ephemeral_pem=public_key_pem(bob_eph))
    bob_sig = signed_data(pki['bob_private'], bob_transcript)
    assert check_signature(bob_identity, bob_transcript, bob_sig)
    logs.append('6. Bob cũng ký B=bG; Alice xác thực chứng thư và chữ ký Bob: HỢP LỆ.')
    salt = secrets.token_bytes(32)
    context = b'BTL2-authenticated-ECDH-v1-' + session_id.encode('ascii')
    ka = ecdh_session_key(alice_eph, bob_eph.public_key(), salt, context)
    kb = ecdh_session_key(bob_eph, alice_eph.public_key(), salt, context)
    assert ka == kb
    packet = encrypt(ka, message.encode('utf-8'), make_aad('Alice', 'Bob', 1), algorithm)
    bob_read = decrypt(kb, packet).decode('utf-8')
    logs.append('7. Chỉ Alice và Bob tính được khóa phiên chung; dữ liệu AEAD gửi thành công.')
    logs.append('8. Eve không có khóa phiên vì không thay được giá trị ECDH có chữ ký.')
    return {
        'mode': 'DH có chữ ký + chứng thư', 'mitm_success': False,
        'ca_root_subject': pki['ca_root']['subject'],
        'alice_cert_subject': pki['alice_cert']['subject'],
        'eve_cert_subject': pki['eve_cert']['subject'],
        'substituted_signature_valid': substituted_signature_ok,
        'eve_certificate_accepted_as_alice': not eve_subject_rejected,
        'legitimate_signature_valid': original_signature_ok,
        'alice_bob_keys_match': ka == kb,
        'session_key_sha256': key_fingerprint(ka),
        'bob_received': bob_read, 'packet': packet, 'log': logs,
    }
