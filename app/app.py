"""Flask demonstration UI for B.2.5/B.2.6 and toy ECDSA (not production TLS)."""
from __future__ import annotations

import json
from pathlib import Path
from flask import Flask, jsonify, render_template, request
from function.key_exchange import toy_dh, toy_dh_mitm, exchange_ecdh, create_ecdh_party, ecdh_session_key
from function.aead import roundtrip_demo, ALGORITHMS
from function.mitm import unauthenticated_mitm, authenticated_mitm
from function.toy_ecdsa import example
import secrets

app = Flask(__name__)
app.json.ensure_ascii = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


def _payload():
    if not request.is_json or not isinstance(request.get_json(silent=True), dict):
        raise ValueError('Cần gửi JSON object')
    return request.get_json()


def _message(body):
    text = body.get('message', 'Xin chào Bob!')
    if not isinstance(text, str) or len(text) > 200 or not text:
        raise ValueError('Thông điệp phải có 1–200 ký tự')
    return text


def _algorithm(body):
    a = body.get('algorithm', ALGORITHMS[0])
    if a not in ALGORITHMS:
        raise ValueError('Thuật toán AEAD không được hỗ trợ')
    return a


@app.errorhandler(ValueError)
def bad_request(err):
    return jsonify({'error': str(err)}), 400


@app.get('/')
def index():
    return render_template('index.html')


@app.get('/api/toy-dh')
def endpoint_toy_dh():
    return jsonify({'exchange': toy_dh(), 'mitm': toy_dh_mitm()})


@app.get('/api/ecdh')
def endpoint_ecdh():
    return jsonify(exchange_ecdh())


@app.post('/api/aead')
def endpoint_aead():
    body = _payload()
    alice, bob = create_ecdh_party(), create_ecdh_party()
    salt = secrets.token_bytes(32)
    ka = ecdh_session_key(alice, bob.public_key(), salt)
    kb = ecdh_session_key(bob, alice.public_key(), salt)
    assert ka == kb
    result = roundtrip_demo(ka, _message(body), _algorithm(body))
    result['key_match'] = True
    return jsonify(result)


@app.post('/api/mitm')
def endpoint_mitm():
    body = _payload()
    message, algorithm = _message(body), _algorithm(body)
    return jsonify({
        'without_auth': unauthenticated_mitm(message, algorithm),
        'with_auth': authenticated_mitm(message, algorithm),
    })


@app.get('/api/toy-ecdsa')
def endpoint_toy_ecdsa():
    return jsonify(example())


@app.get('/api/benchmarks')
def endpoint_benchmarks():
    path = Path(__file__).with_name('benchmark_results.json')
    if not path.is_file():
        return jsonify({'error': 'Chưa có kết quả đo. Chạy python benchmark_crypto.py --runs 20'}), 404
    return jsonify(json.loads(path.read_text(encoding='utf-8')))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
