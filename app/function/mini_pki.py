"""Minimal JSON CA for MITM demo. Not an X.509 implementation."""
from __future__ import annotations
import json
import secrets
from datetime import datetime, timedelta, timezone
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')).encode('utf-8')


def signed_data(private_key, data: dict) -> str:
    digest = SHA256.new(canonical(data))
    return DSS.new(private_key, 'fips-186-3').sign(digest).hex()


def check_signature(public_key, data: dict, signature: str) -> bool:
    try:
        DSS.new(public_key, 'fips-186-3').verify(
            SHA256.new(canonical(data)), bytes.fromhex(signature))
        return True
    except (ValueError, TypeError):
        return False


def issue_certificate(ca_private, subject: str, owner_public, *,
                      issuer: str = 'Demo-CA', lifetime_days: int = 1) -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        'subject': subject, 'issuer': issuer,
        'public_key': owner_public.export_key(format='PEM'),
        'serial': secrets.token_hex(12),
        'not_before': (now - timedelta(minutes=1)).isoformat(),
        'not_after': (now + timedelta(days=lifetime_days)).isoformat(),
    }
    return {**payload, 'signature': signed_data(ca_private, payload)}


def verify_certificate(cert: dict, *, ca_public, expected_subject: str,
                       issuer: str = 'Demo-CA', revoked_serials=()) -> ECC.EccKey:
    """Trust anchor (ca_public) must be configured independently of the received cert."""
    required = ('subject', 'issuer', 'public_key', 'serial', 'not_before', 'not_after', 'signature')
    if not all(k in cert for k in required):
        raise ValueError('Chứng thư thiếu trường bắt buộc')
    if cert['issuer'] != issuer:
        raise ValueError('Sai tổ chức phát hành')
    if cert['subject'] != expected_subject:
        raise ValueError('Tên chủ thể không khớp')
    if cert['serial'] in revoked_serials:
        raise ValueError('Chứng thư đã bị thu hồi (CRL)')
    payload = {k: cert[k] for k in required if k != 'signature'}
    if not check_signature(ca_public, payload, cert['signature']):
        raise ValueError('Chữ ký CA sai (chứng thư bị sửa)')
    try:
        now = datetime.now(timezone.utc)
        begin = datetime.fromisoformat(cert['not_before'])
        end = datetime.fromisoformat(cert['not_after'])
        if begin.tzinfo is None or end.tzinfo is None or not begin <= now <= end:
            raise ValueError('Chứng thư chưa hiệu lực hoặc hết hạn')
        public = ECC.import_key(cert['public_key'])
        if public.has_private() or public.curve != 'NIST P-256':
            raise ValueError('Khóa chứng thư phải là khóa công khai P-256')
        return public
    except (TypeError, KeyError) as exc:
        raise ValueError('Chứng thư không hợp lệ') from exc


def make_demo_pki() -> dict:
    ca = ECC.generate(curve='P-256')
    alice = ECC.generate(curve='P-256')
    bob = ECC.generate(curve='P-256')
    eve = ECC.generate(curve='P-256')
    root = issue_certificate(ca, 'Demo-CA', ca.public_key())
    # The pinned CA public key is the trust anchor, not a key claimed by a remote peer.
    verify_certificate(root, ca_public=ca.public_key(), expected_subject='Demo-CA')
    return {
        'ca_private': ca, 'alice_private': alice, 'bob_private': bob,
        'eve_private': eve, 'ca_root': root,
        'alice_cert': issue_certificate(ca, 'Alice', alice.public_key()),
        'bob_cert': issue_certificate(ca, 'Bob', bob.public_key()),
        'eve_cert': issue_certificate(ca, 'Eve', eve.public_key()),
    }
