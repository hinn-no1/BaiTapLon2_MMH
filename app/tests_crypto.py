"""Các kiểm thử mật mã phần B.2.5/B.2.6 và ECDSA số nhỏ.

Chạy: python -m unittest -v tests_crypto
Các test cần PyCryptodome tự động đánh dấu SKIP nếu thư viện chưa được cài.
"""
import hashlib
import unittest
from io import BytesIO

from function.toy_ecdsa import example, add, mul, G, N, sign, verify, on_curve
from function.hash_hmac import create_hmac, verify_hmac, benchmark_file

try:
    from Crypto.PublicKey import ECC
    from function.key_exchange import (toy_dh, toy_dh_mitm, exchange_ecdh,
                                       RFC3526_GROUP14_P, dh2048_keypair, dh2048_secret)
    from function.aead import encrypt, decrypt, tamper, make_aad
    from function.mitm import unauthenticated_mitm, authenticated_mitm
    from function.mini_pki import make_demo_pki, verify_certificate, issue_certificate
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class TestToyECDSA(unittest.TestCase):
    def test_given_vectors(self):
        v = example()
        self.assertEqual(tuple(v['Q']), (12, 16))
        self.assertEqual(tuple(v['signature']), (16, 6))
        self.assertEqual(tuple(v['verify_point']), (16, 1))
        self.assertTrue(v['valid'])
        self.assertFalse(v['changed_message_valid'])
        self.assertIsNone(mul(N, G))

    def test_all_signatures(self):
        for d in range(1, N):
            for k in range(1, N):
                for h in (0, 1, 7, 10, 22):
                    try:
                        sig = sign(h, d, k)
                    except ValueError:
                        continue
                    self.assertTrue(verify(h, sig, mul(d))[0], (h, d, k, sig))

    def test_group_and_invalid_inputs(self):
        self.assertTrue(on_curve(G))
        self.assertEqual(add(G, None), G)
        self.assertIsNone(add(G, (G[0], (-G[1]) % 17)))
        with self.assertRaises(ValueError):
            sign(10, 7, 0)
        self.assertFalse(verify(10, (0, 6), mul(7))[0])
        self.assertFalse(verify(10, (16, 0), mul(7))[0])


class TestHashHMAC(unittest.TestCase):
    def test_hmac_vector_and_change(self):
        msg = 'The quick brown fox jumps over the lazy dog'
        tag = create_hmac(msg, 'key')
        self.assertEqual(tag, 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8')
        self.assertTrue(verify_hmac(msg, 'key', tag))
        self.assertFalse(verify_hmac(msg + '.', 'key', tag))

    def test_hash_and_benchmark_minimum(self):
        self.assertEqual(hashlib.sha256(b'abc').hexdigest(),
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        with self.assertRaisesRegex(ValueError, 'tối thiểu 10 MB'):
            benchmark_file(BytesIO(b'1234'))


@unittest.skipUnless(HAS_CRYPTO, 'pip install -r requirements.txt')
class TestProtocols(unittest.TestCase):
    def test_toy_dh(self):
        sample = toy_dh()
        self.assertEqual((sample['A'], sample['B'], sample['alice_secret'], sample['bob_secret']),
                         (8, 19, 2, 2))
        attack = toy_dh_mitm()
        self.assertEqual((attack['Alice_Eve_key'], attack['Eve_Bob_key']), (1, 15))
        self.assertTrue(attack['keys_different'])

    def test_ecdh(self):
        self.assertEqual(RFC3526_GROUP14_P.bit_length(), 2048)
        data = exchange_ecdh()
        self.assertTrue(data['key_match'])
        self.assertEqual(data['session_key_bits'], 256)
        self.assertEqual(len(data['session_key_sha256']), 64)
        priv1, pub1 = dh2048_keypair()
        priv2, pub2 = dh2048_keypair()
        self.assertEqual(dh2048_secret(priv1, pub2), dh2048_secret(priv2, pub1))

    def test_aead_integrity(self):
        from Crypto.Random import get_random_bytes
        for algorithm in ('AES-256-GCM', 'ChaCha20-Poly1305'):
            key = get_random_bytes(32)
            aad = make_aad('Alice', 'Bob', 1)
            packet = encrypt(key, b'original text', aad, algorithm)
            self.assertEqual(decrypt(key, packet), b'original text')
            self.assertEqual(len(bytes.fromhex(packet['nonce'])), 12)
            self.assertEqual(len(bytes.fromhex(packet['tag'])), 16)
            for field in ('ciphertext', 'aad'):
                with self.assertRaisesRegex(ValueError, 'thẻ xác thực không hợp lệ'):
                    decrypt(key, tamper(packet, field))
            modified = dict(packet)
            modified['tag'] = '00' * 16
            with self.assertRaisesRegex(ValueError, 'thẻ xác thực không hợp lệ'):
                decrypt(key, modified)
            self.assertNotEqual(packet['nonce'], encrypt(key, b'original text', aad, algorithm)['nonce'])

    def test_mitm(self):
        for algorithm in ('AES-256-GCM', 'ChaCha20-Poly1305'):
            raw = unauthenticated_mitm('Test MITM', algorithm)
            self.assertTrue(raw['mitm_success'])
            self.assertTrue(raw['keys_different'])
            self.assertNotEqual(raw['alice_eve_key_sha256'], raw['eve_bob_key_sha256'])
            self.assertEqual(raw['eve_read'], 'Test MITM')
            self.assertEqual(raw['bob_received'], 'Test MITM')
            auth = authenticated_mitm('Test MITM', algorithm)
            self.assertFalse(auth['mitm_success'])
            self.assertFalse(auth['substituted_signature_valid'])
            self.assertFalse(auth['eve_certificate_accepted_as_alice'])
            self.assertTrue(auth['alice_bob_keys_match'])
            self.assertEqual(auth['bob_received'], 'Test MITM')

    def test_pki_cert_errors(self):
        pki = make_demo_pki()
        ca = pki['ca_private'].public_key()
        cert = pki['alice_cert']
        self.assertTrue(verify_certificate(cert, ca_public=ca, expected_subject='Alice'))
        with self.assertRaisesRegex(ValueError, 'Tên chủ thể'):
            verify_certificate(cert, ca_public=ca, expected_subject='Bob')
        with self.assertRaisesRegex(ValueError, 'thu hồi'):
            verify_certificate(cert, ca_public=ca, expected_subject='Alice', revoked_serials=(cert['serial'],))
        forged = dict(cert, public_key=pki['eve_private'].public_key().export_key(format='PEM'))
        with self.assertRaisesRegex(ValueError, 'Chữ ký CA sai'):
            verify_certificate(forged, ca_public=ca, expected_subject='Alice')
        expired = issue_certificate(pki['ca_private'], 'Alice',
                                    pki['alice_private'].public_key(), lifetime_days=-1)
        with self.assertRaisesRegex(ValueError, 'hết hạn'):
            verify_certificate(expired, ca_public=ca, expected_subject='Alice')


if __name__ == '__main__':
    unittest.main(verbosity=2)
