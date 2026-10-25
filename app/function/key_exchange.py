"""B.2.5: toy DH; ECDH P-256 + HKDF-SHA256; RFC3526 DH-2048 reference."""
from __future__ import annotations

import hashlib
import secrets
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.number import isPrime

RFC3526_GROUP14_P = int('''
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF
FFFFFFFF'''.replace(' ', '').replace('\n', ''), 16)


def toy_dh(p: int = 23, g: int = 5, a: int = 6, b: int = 15) -> dict:
    """Small-group DH is ONLY a classroom demonstration; not secure."""
    if any(type(v) is not int for v in (p, g, a, b)):
        raise ValueError('p, g, a, b phải là số nguyên')
    if not 5 <= p <= 65535 or not isPrime(p):
        raise ValueError('DH số nhỏ yêu cầu p nguyên tố trong [5, 65535]')
    if not 2 <= g <= p - 2:
        raise ValueError('g phải thuộc [2, p-2]')
    remaining, factors, divisor = p - 1, set(), 2
    while divisor * divisor <= remaining:
        while remaining % divisor == 0:
            factors.add(divisor)
            remaining //= divisor
        divisor += 1
    if remaining > 1:
        factors.add(remaining)
    if any(pow(g, (p - 1) // q, p) == 1 for q in factors):
        raise ValueError('g phải là phần tử sinh modulo p')
    if not (1 <= a < p - 1 and 1 <= b < p - 1):
        raise ValueError('Số mũ phải thuộc [1, p-2].')
    A, B = pow(g, a, p), pow(g, b, p)
    alice = pow(B, a, p)
    bob = pow(A, b, p)
    assert alice == bob
    return {'p': p, 'g': g, 'a': a, 'b': b,
            'A': A, 'B': B, 'alice_secret': alice, 'bob_secret': bob}


def create_ecdh_party():
    """Generate an ephemeral P-256 ECDH key pair."""
    return ECC.generate(curve='P-256')


def hkdf_session(shared_secret: bytes, salt: bytes, context: bytes = b'BTL2-ECDH-P256-v1') -> bytes:
    if not salt:
        raise ValueError('HKDF salt cannot be empty')
    return HKDF(shared_secret, 32, salt, SHA256, context=context)


def ecdh_session_key(my_private, peer_public, salt: bytes,
                     context: bytes = b'BTL2-ECDH-P256-v1') -> bytes:
    """Import/validate peer P-256 public point using PyCryptodome ECC.

    HKDF is applied inside Crypto.Protocol.DH.key_agreement.
    """
    if my_private.curve != 'NIST P-256' or peer_public.curve != 'NIST P-256':
        raise ValueError('Only NIST P-256 keys are supported')
    if not my_private.has_private() or peer_public.has_private():
        raise ValueError('Expected a private local key and public peer key')
    return key_agreement(
        eph_priv=my_private, eph_pub=peer_public,
        kdf=lambda raw: hkdf_session(raw, salt, context),
    )


def public_key_pem(private_key) -> str:
    return private_key.public_key().export_key(format='PEM')


def exchange_ecdh() -> dict:
    """End-to-end ECDH demo; keys intentionally NOT returned in the API."""
    alice = create_ecdh_party()
    bob = create_ecdh_party()
    salt = secrets.token_bytes(32)
    context = b'BTL2-Alice-Bob-demo-v1'
    ka = ecdh_session_key(alice, bob.public_key(), salt, context)
    kb = ecdh_session_key(bob, alice.public_key(), salt, context)
    assert ka == kb
    return {
        'alice_public_key': public_key_pem(alice),
        'bob_public_key': public_key_pem(bob),
        'hkdf_salt': salt.hex(), 'hkdf_context': context.decode(),
        'key_match': ka == kb,
        'session_key_sha256': hashlib.sha256(ka).hexdigest(),
        'session_key_bits': 256,
    }


def dh2048_secret(a: int, B: int) -> int:
    p = RFC3526_GROUP14_P
    q = (p - 1) // 2
    if not 2 <= B <= p - 2 or pow(B, q, p) != 1:
        raise ValueError('Invalid DH-2048 peer public value/subgroup')
    return pow(B, a, p)


def dh2048_keypair():
    a = secrets.randbelow((RFC3526_GROUP14_P - 1) // 2 - 3) + 2
    return a, pow(2, a, RFC3526_GROUP14_P)


def toy_dh_mitm() -> dict:
    """Reproducible numeric MITM log for the written answer C1 (toy group!)."""
    p, g = 23, 5
    a, b, e_to_bob, e_to_alice = 6, 15, 7, 11
    A, B = pow(g, a, p), pow(g, b, p)
    EB, EA = pow(g, e_to_bob, p), pow(g, e_to_alice, p)
    k_ae = pow(EA, a, p)
    k_ea = pow(A, e_to_alice, p)
    k_eb = pow(B, e_to_bob, p)
    k_be = pow(EB, b, p)
    assert k_ae == k_ea and k_eb == k_be and k_ae != k_eb
    return {
        'Alice_public': A, 'Bob_public': B, 'Eve_to_Bob_public': EB,
        'Eve_to_Alice_public': EA, 'Alice_Eve_key': k_ae,
        'Eve_Bob_key': k_eb, 'keys_different': k_ae != k_eb,
        'log': [
            'Alice gửi A=8, Eve chặn; Bob nhận EB=17 thay vì A=8.',
            'Bob gửi B=19, Eve chặn; Alice nhận EA=22 thay vì B=19.',
            'Alice tính 22^6 mod 23 = 1; Eve tính 8^11 mod 23 = 1.',
            'Bob tính 17^15 mod 23 = 15; Eve tính 19^7 mod 23 = 15.',
            'Có hai khóa 1 và 15: Eve có thể giải mã rồi mã hóa lại nếu dùng các khóa tương ứng.',
        ],
    }
