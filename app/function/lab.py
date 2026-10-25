"""Stateful classroom workflow: identity keys -> JSON PKI -> ECDH -> AEAD.

All parties live in this backend. This is deliberately a simulator, not a
network authentication protocol or a substitute for TLS / X.509.
"""
import copy
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from .key_management import generate_entity_keys
from .signatures import ALGORITHMS, sign_bytes, verify_bytes, sign_and_verify_demo
from .key_exchange import create_ecdh_party, ecdh_session_key, public_key_pem
from .aead import encrypt, decrypt, make_aad, tamper


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def describe_data(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        text = None
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'text_preview': text[:200] if text is not None else None,
            'hex_preview': data[:64].hex(), 'preview_truncated': len(data) > 200}


def hash_demo(data, key, supplied_tag=None):
    if not isinstance(key, str) or not 1 <= len(key) <= 200:
        raise ValueError('Khóa HMAC phải có 1–200 ký tự')
    result = {}
    for name in ('sha256', 'sha1', 'md5'):
        start = time.perf_counter()
        digest = hashlib.new(name, data).hexdigest()
        result[name] = {'digest': digest, 'time_ms': (time.perf_counter()-start)*1000}
    tag = hmac.new(key.encode('utf-8'), data, hashlib.sha256).hexdigest()
    if supplied_tag is None or supplied_tag == '':
        supplied_tag = tag
    try:
        raw_tag = bytes.fromhex(supplied_tag)
    except (ValueError, TypeError):
        raise ValueError('Thẻ HMAC phải là chuỗi hex hợp lệ') from None
    if len(raw_tag) != 32:
        raise ValueError('Thẻ HMAC cần đúng 32 byte')
    altered = data[:-1] + bytes([data[-1] ^ 1]) if data else b'\x01'
    return {'input': describe_data(data), 'hashes': result, 'hmac_sha256': tag,
            'supplied_tag_valid': hmac.compare_digest(bytes.fromhex(tag), raw_tag),
            'changed_content_valid': hmac.compare_digest(tag, hmac.new(
                key.encode('utf-8'), altered, hashlib.sha256).hexdigest()),
            'note': 'SHA-1 và MD5 chỉ dùng so sánh; HMAC sử dụng SHA-256.'}


class Lab:
    def __init__(self, alice='Alice', bob='Bob', ca='Demo-CA', algorithm='ECDSA'):
        names = (alice, bob, ca)
        if any(not isinstance(n, str) or not n.strip() or len(n) > 50 for n in names):
            raise ValueError('Tên thực thể phải có 1–50 ký tự')
        if len(set(names + ('Eve',))) != 4:
            raise ValueError('Tên Alice, Bob, CA phải khác nhau và khác Eve')
        if algorithm not in ALGORITHMS:
            raise ValueError('Thuật toán chữ ký không được hỗ trợ')
        self.algorithm = algorithm
        self.names = dict(zip(('alice', 'bob', 'ca', 'eve'), names + ('Eve',)))
        self.keys = {role: generate_entity_keys(name, algorithm)
                     for role, name in self.names.items()}
        self.certificates = {}
        self.revoked = set()

    def public_view(self):
        return {'signature_algorithm': self.algorithm,
                'entities': {role: {k: v for k, v in data.items() if k != 'private_key'}
                             for role, data in self.keys.items()},
                'note': 'Fingerprint = 16 byte đầu của SHA-256 trên khóa công khai PEM.'}

    def issue(self, role, lifetime_days=1):
        now = datetime.now(timezone.utc)
        body = {'subject': self.names[role], 'issuer': self.names['ca'],
                'public_key': self.keys[role]['public_key_pem'],
                'serial': secrets.token_hex(12),
                'not_before': (now-timedelta(minutes=1)).isoformat(),
                'not_after': (now+timedelta(days=lifetime_days)).isoformat(),
                'signature_algorithm': self.algorithm}
        return {**body, 'signature': sign_bytes(self.keys['ca']['private_key'],
                                               canonical(body), self.algorithm).hex()}

    def issue_all(self):
        self.certificates = {role: self.issue(role) for role in self.keys}
        self.revoked.clear()
        return {'certificates': self.certificates, 'format': 'JSON demo, không phải X.509',
                'chain': self.check('valid')}

    def verify_cert(self, cert, subject, revoked=()):
        required = ('subject', 'issuer', 'public_key', 'serial', 'not_before', 'not_after',
                    'signature_algorithm', 'signature')
        if not isinstance(cert, dict) or not all(k in cert for k in required):
            raise ValueError('Chứng thư thiếu trường')
        if cert['signature_algorithm'] != self.algorithm:
            raise ValueError('Sai thuật toán chứng thư')
        if cert['issuer'] != self.names['ca']:
            raise ValueError('Sai CA phát hành')
        if cert['subject'] != subject:
            raise ValueError('Tên chủ thể không khớp')
        if cert['serial'] in revoked:
            raise ValueError('Chứng thư đã bị thu hồi')
        body = {k: cert[k] for k in required if k != 'signature'}
        try:
            signature = bytes.fromhex(cert['signature'])
        except (ValueError, TypeError):
            raise ValueError('Chữ ký CA không hợp lệ') from None
        if not verify_bytes(self.keys['ca']['private_key'].public_key(), canonical(body),
                            signature, self.algorithm):
            raise ValueError('Chữ ký CA không hợp lệ')
        try:
            start, end = (datetime.fromisoformat(cert[k]) for k in ('not_before', 'not_after'))
            now = datetime.now(timezone.utc)
            if start.tzinfo is None or end.tzinfo is None or not start <= now <= end:
                raise ValueError('Chứng thư chưa hiệu lực hoặc đã hết hạn')
            return serialization.load_pem_public_key(cert['public_key'].encode('utf-8'))
        except (TypeError, AttributeError):
            raise ValueError('Chứng thư không hợp lệ') from None

    def require_certs(self):
        if not self.certificates:
            raise ValueError('Hãy cấp chứng thư trước')

    def check(self, scenario):
        self.require_certs()
        if scenario not in ('valid', 'tampered', 'expired', 'wrong_subject', 'revoked'):
            raise ValueError('Kịch bản chứng thư không được hỗ trợ')
        cert = copy.deepcopy(self.certificates['alice'])
        subject, revoked = self.names['alice'], set(self.revoked)
        if scenario == 'tampered':
            cert['public_key'] = self.keys['eve']['public_key_pem']
        elif scenario == 'expired':
            cert = self.issue('alice', lifetime_days=-1)
        elif scenario == 'wrong_subject':
            subject = self.names['bob']
        elif scenario == 'revoked':
            revoked.add(cert['serial'])
        try:
            self.verify_cert(self.certificates['ca'], self.names['ca'])
            self.verify_cert(cert, subject, revoked)
            return {'valid': True, 'scenario': scenario, 'reason': 'Chuỗi CA → chủ thể hợp lệ'}
        except ValueError as exc:
            return {'valid': False, 'scenario': scenario, 'reason': str(exc)}

    def sign(self, data):
        key = self.keys['alice']['private_key']
        result = sign_and_verify_demo(key, key.public_key(), data, self.algorithm,
                                      self.keys['eve']['private_key'])
        result.update(signer=self.names['alice'], input=describe_data(data))
        return result

    def channel(self, data, algorithm, mode):
        if mode not in ('authenticated', 'unauthenticated'):
            raise ValueError('Chế độ DH không hợp lệ')
        alice, bob = create_ecdh_party(), create_ecdh_party()
        aad = make_aad(self.names['alice'], self.names['bob'], 1)
        logs, evidence = [], {}
        sid = secrets.token_hex(16)
        if mode == 'unauthenticated':
            ea, eb = create_ecdh_party(), create_ecdh_party()
            sa, sb = secrets.token_bytes(32), secrets.token_bytes(32)
            context = ('BTL2-unauth-' + sid).encode('ascii')
            ka = ecdh_session_key(alice, ea.public_key(), sa, context)
            kea = ecdh_session_key(ea, alice.public_key(), sa, context)
            kb = ecdh_session_key(bob, eb.public_key(), sb, context)
            keb = ecdh_session_key(eb, bob.public_key(), sb, context)
            first = encrypt(ka, data, aad, algorithm)
            seen = decrypt(kea, first)
            packet = encrypt(keb, seen, aad, algorithm)
            decoded = decrypt(kb, packet)
            evidence = {'eve_read': describe_data(seen), 'keys_different': ka != kb,
                        'alice_eve_key_sha256': hashlib.sha256(ka).hexdigest(),
                        'eve_bob_key_sha256': hashlib.sha256(kb).hexdigest()}
            logs = ['Eve thay khóa ECDH của cả hai bên.',
                    'Hai cặp Alice–Eve và Eve–Bob dẫn xuất hai khóa khác nhau bằng HKDF.',
                    'Eve giải mã được dữ liệu rồi mã hóa lại với tag hợp lệ cho Bob.']
        else:
            self.require_certs()
            self.verify_cert(self.certificates['ca'], self.names['ca'])
            ap = self.verify_cert(self.certificates['alice'], self.names['alice'], self.revoked)
            bp = self.verify_cert(self.certificates['bob'], self.names['bob'], self.revoked)
            salt = secrets.token_bytes(32)
            transcript = {'session_id': sid, 'alice': self.names['alice'], 'bob': self.names['bob'],
                          'alice_ephemeral': public_key_pem(alice), 'bob_ephemeral': public_key_pem(bob),
                          'salt': salt.hex(), 'aead': algorithm}
            raw = canonical(transcript)
            siga = sign_bytes(self.keys['alice']['private_key'], raw, self.algorithm)
            sigb = sign_bytes(self.keys['bob']['private_key'], raw, self.algorithm)
            if not verify_bytes(ap, raw, siga, self.algorithm) or not verify_bytes(bp, raw, sigb, self.algorithm):
                raise ValueError('Chữ ký trao đổi khóa không hợp lệ')
            forged = dict(transcript, alice_ephemeral=public_key_pem(create_ecdh_party()))
            substitution_valid = verify_bytes(ap, canonical(forged), siga, self.algorithm)
            try:
                self.verify_cert(self.certificates['eve'], self.names['alice'])
                eve_accepted = True
            except ValueError:
                eve_accepted = False
            if substitution_valid or eve_accepted:
                raise ValueError('Lỗi xác thực: kịch bản giả mạo không bị chặn')
            context = b'BTL2-auth-' + hashlib.sha256(raw).digest()
            ka = ecdh_session_key(alice, bob.public_key(), salt, context)
            kb = ecdh_session_key(bob, alice.public_key(), salt, context)
            if ka != kb:
                raise ValueError('Khóa phiên không khớp')
            packet = encrypt(ka, data, aad, algorithm)
            decoded = decrypt(kb, packet)
            evidence = {'alice_bob_keys_match': ka == kb,
                        'session_key_sha256': hashlib.sha256(ka).hexdigest(),
                        'substituted_signature_valid': substitution_valid,
                        'eve_certificate_accepted_as_alice': eve_accepted,
                        'signature_algorithm': self.algorithm, 'transcript': transcript,
                        'alice_signature_hex': siga.hex(), 'bob_signature_hex': sigb.hex()}
            logs = ['Kiểm tra chuỗi chứng thư CA → Alice và CA → Bob.',
                    'Hai bên ký toàn bộ bản ghi trao đổi khóa; xác minh thành công.',
                    'Eve thay khóa: chữ ký sai. Eve dùng chứng thư của Eve: sai chủ thể.',
                    'Nhánh hợp lệ dẫn xuất khóa bằng ECDH + HKDF; Bob giải mã AEAD thành công.']
        checks = {}
        for field in ('ciphertext', 'aad'):
            altered = tamper(packet, field) if packet[field] else dict(packet, ciphertext='01')
            try:
                decrypt(kb, altered)
                checks[field + '_tamper_rejected'] = False
            except ValueError:
                checks[field + '_tamper_rejected'] = True
        view = {k: v for k, v in packet.items() if k != 'ciphertext'}
        view.update(ciphertext_hex_preview=packet['ciphertext'][:256],
                    ciphertext_bytes=len(decoded), ciphertext_truncated=len(packet['ciphertext']) > 256)
        result = {'mode': mode, 'mitm_success': mode == 'unauthenticated',
                  'bob_received': describe_data(decoded), 'roundtrip_match': decoded == data,
                  'packet': view, 'log': logs, **evidence, **checks}
        return result, packet, decoded
