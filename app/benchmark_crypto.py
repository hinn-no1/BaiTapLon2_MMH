"""B.2.7 benchmark: >=20 repetitions per operation. Run: python benchmark_crypto.py --runs 20.

Measures are platform-dependent. Output JSON + CSV in app/; never claim the numbers
are deterministic or transferable to a different computer / Python crypto backend.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics as stats
import time
from pathlib import Path
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from function.aead import encrypt, decrypt, make_aad
from function.key_exchange import create_ecdh_party, ecdh_session_key, dh2048_keypair, dh2048_secret
from Crypto import __version__ as crypto_version


def ms(fn):
    begin = time.perf_counter_ns()
    result = fn()
    return (time.perf_counter_ns() - begin) / 1e6, result


def describe(values):
    return {
        'runs': len(values), 'mean_ms': round(stats.mean(values), 5),
        'median_ms': round(stats.median(values), 5),
        'stdev_ms': round(stats.stdev(values), 5) if len(values) > 1 else 0.0,
        'min_ms': round(min(values), 5), 'max_ms': round(max(values), 5),
    }


def pem_size_bytes(key):
    """RSA exports bytes; ECC exports str. Count the serialized PEM bytes."""
    pem = key.export_key(format='PEM')
    return len(pem.encode('utf-8') if isinstance(pem, str) else pem)


def measure_signatures(runs, result):
    message = b'Mat ma hoc - BTL2 benchmark - same message for all algorithms'
    h = SHA256.new(message)
    for algorithm in ('RSA-2048', 'RSA-3072', 'ECDSA-P256'):
        keygen_times = []
        for _ in range(runs):
            elapsed, _ = ms(lambda: ECC.generate(curve='P-256') if algorithm == 'ECDSA-P256'
                            else RSA.generate(int(algorithm.split('-')[1])))
            keygen_times.append(elapsed)
        key = ECC.generate(curve='P-256') if algorithm == 'ECDSA-P256' else RSA.generate(int(algorithm.split('-')[1]))
        public = key.public_key()
        sign_times, verify_times, sig_sizes = [], [], []
        for _ in range(runs):
            if algorithm == 'ECDSA-P256':
                elapsed, signature = ms(lambda: DSS.new(key, 'fips-186-3').sign(h))
                check_elapsed, _ = ms(lambda: DSS.new(public, 'fips-186-3').verify(h, signature))
            else:
                elapsed, signature = ms(lambda: pss.new(key).sign(h))
                check_elapsed, _ = ms(lambda: pss.new(public).verify(h, signature))
            sign_times.append(elapsed)
            verify_times.append(check_elapsed)
            sig_sizes.append(len(signature))
        result['signatures'][algorithm] = {
            'keygen': describe(keygen_times), 'sign': describe(sign_times),
            'verify': describe(verify_times), 'public_key_pem_bytes': pem_size_bytes(public),
            'private_key_pem_bytes': pem_size_bytes(key),
            'signature_bytes': sig_sizes[0],
        }


def measure_key_exchange(runs, result):
    for algorithm in ('ECDH-P256', 'DH-2048'):
        keygens, agreements = [], []
        for _ in range(runs):
            if algorithm == 'ECDH-P256':
                elapsed, local = ms(create_ecdh_party)
                peer = create_ecdh_party()
                salt = get_random_bytes(32)
                agreement, _ = ms(lambda: ecdh_session_key(local, peer.public_key(), salt))
            else:
                elapsed, local = ms(dh2048_keypair)
                peer_priv, peer_pub = dh2048_keypair()
                agreement, secret = ms(lambda: dh2048_secret(local[0], peer_pub))
                assert secret == dh2048_secret(peer_priv, local[1])
            keygens.append(elapsed)
            agreements.append(agreement)
        result['key_exchange'][algorithm] = {
            'keypair_generation': describe(keygens), 'one_side_agreement': describe(agreements)
        }


def measure_aead(runs, result):
    plaintext = get_random_bytes(1024 * 1024)
    aad = make_aad('Alice', 'Bob', 1)
    key = get_random_bytes(32)
    for algorithm in ('AES-256-GCM', 'ChaCha20-Poly1305'):
        encrypt_times, decrypt_times, packets = [], [], []
        for _ in range(runs):
            elapsed, packet = ms(lambda: encrypt(key, plaintext, aad, algorithm))
            encrypt_times.append(elapsed)
            packets.append(packet)
        assert len({p['nonce'] for p in packets}) == runs, 'Nonce collision: abort'
        for packet in packets:
            elapsed, decoded = ms(lambda: decrypt(key, packet))
            assert decoded == plaintext
            decrypt_times.append(elapsed)
        result['aead'][algorithm] = {
            'plaintext_bytes': len(plaintext),
            'encryption': describe(encrypt_times), 'decryption': describe(decrypt_times),
            'nonce_bytes': 12, 'tag_bytes': 16,
            'ciphertext_bytes': len(bytes.fromhex(packets[0]['ciphertext'])),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runs', type=int, default=20)
    args = parser.parse_args()
    if args.runs < 20:
        parser.error('B.2.7 requires at least 20 runs')
    result = {
        'metadata': {'python': platform.python_version(), 'pycryptodome': crypto_version,
                     'system': platform.platform(), 'runs_per_operation': args.runs,
                     'timer': 'time.perf_counter_ns', 'time_unit': 'milliseconds',
                     'notes': 'Local machine measurements, including Python call overhead; no network RTT'},
        'signatures': {}, 'key_exchange': {}, 'aead': {},
    }
    start = time.perf_counter()
    print(f'Measuring signatures, ECDH/DH and 1 MiB AEAD (n={args.runs})...', flush=True)
    measure_signatures(args.runs, result)
    print('Signatures OK', flush=True)
    measure_key_exchange(args.runs, result)
    print('Key exchange OK', flush=True)
    measure_aead(args.runs, result)
    print('AEAD OK', flush=True)
    result['metadata']['total_elapsed_seconds'] = round(time.perf_counter() - start, 3)
    out = Path(__file__).with_name('benchmark_results.json')
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    rows = []
    for category in ('signatures', 'key_exchange', 'aead'):
        for algo, metrics in result[category].items():
            for operation, summary in metrics.items():
                if isinstance(summary, dict) and 'mean_ms' in summary:
                    rows.append({'category': category, 'algorithm': algo, 'operation': operation, **summary})
    csv_path = out.with_suffix('.csv')
    with csv_path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader(); writer.writerows(rows)
    print('Saved:', out, 'and', csv_path)
    for row in rows:
        print(f"{row['category']:12} {row['algorithm']:20} {row['operation']:20} {row['mean_ms']:>12.5f} ms")

if __name__ == '__main__':
    main()
