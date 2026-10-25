"""Web workflow state is server-side; cookies contain only a random session ID."""
from io import BytesIO
import json
import secrets
import threading
import time
from flask import Blueprint, jsonify, request, session, send_file
from werkzeug.utils import secure_filename
from function.lab import Lab, hash_demo, describe_data
from function.kerberos_demo import KerberosDemo
from function.aead import ALGORITHMS
from function.key_exchange import toy_dh

bp = Blueprint('lab', __name__)
states, state_lock = {}, threading.RLock()
FILE_LIMIT = 10 * 1024 * 1024


def body():
    data = request.get_json(silent=True)
    if not request.is_json or not isinstance(data, dict):
        raise ValueError('Cần gửi JSON object')
    return data


def state():
    now = time.monotonic()
    for key in list(states):
        if now-states[key]['touched'] > 1800:
            del states[key]
    sid = session.get('lab_id')
    if sid not in states:
        if len(states) >= 32:
            raise ValueError('Đã đủ phiên mô phỏng; hãy khởi động lại ứng dụng demo')
        sid = secrets.token_hex(24)
        session['lab_id'] = sid
        states[sid] = {'touched': now, 'kerberos': KerberosDemo()}
    states[sid]['touched'] = now
    return states[sid]


def lab(s):
    if 'lab' not in s:
        raise ValueError('Hãy sinh khóa Alice, Bob và CA trước')
    return s['lab']


def chosen_lab(s, data):
    current = lab(s)
    if data.get('signature_algorithm', current.algorithm) != current.algorithm:
        raise ValueError('Bạn đã đổi thuật toán; hãy sinh khóa và cấp chứng thư lại')
    return current


def data_for(s, data):
    source = data.get('source', 'text')
    if source == 'file':
        if 'uploaded' not in s:
            raise ValueError('Hãy tải tệp lên trước')
        return s['uploaded'], s['filename']
    if source != 'text':
        raise ValueError('Nguồn dữ liệu phải là text hoặc file')
    message = data.get('message', '')
    if not isinstance(message, str) or not 1 <= len(message) <= 200:
        raise ValueError('Thông điệp phải có 1–200 ký tự')
    return message.encode('utf-8'), 'thong_diep.txt'


@bp.post('/api/lab/setup')
def setup():
    data = body()
    prepared = Lab(data.get('alice', 'Alice'), data.get('bob', 'Bob'),
                   data.get('ca', 'Demo-CA'), data.get('signature_algorithm', 'ECDSA'))
    with state_lock:
        s = state()
        s['lab'] = prepared
        s.pop('packet', None)
        s.pop('decoded', None)
        return jsonify(prepared.public_view())


@bp.post('/api/lab/upload')
def upload():
    uploaded = request.files.get('file')
    if uploaded is None or not uploaded.filename:
        raise ValueError('Hãy chọn một tệp')
    data = uploaded.read(FILE_LIMIT+1)
    if len(data) > FILE_LIMIT:
        raise ValueError('Tệp tối đa 10 MiB')
    with state_lock:
        s = state()
        s['uploaded'] = data
        s['filename'] = secure_filename(uploaded.filename) or 'tep_du_lieu.bin'
        return jsonify(filename=s['filename'], **describe_data(data))


@bp.post('/api/lab/certificates')
def certificates():
    body()
    with state_lock:
        return jsonify(lab(state()).issue_all())


@bp.post('/api/lab/check-certificate')
def check_certificate():
    data = body()
    with state_lock:
        return jsonify(lab(state()).check(data.get('scenario', 'valid')))


@bp.post('/api/lab/hash')
def hashes():
    data = body()
    with state_lock:
        raw, _ = data_for(state(), data)
        return jsonify(hash_demo(raw, data.get('hmac_key', ''), data.get('hmac_tag')))


@bp.post('/api/lab/sign')
def sign():
    data = body()
    with state_lock:
        s = state()
        raw, _ = data_for(s, data)
        return jsonify(chosen_lab(s, data).sign(raw))


@bp.post('/api/lab/channel')
def channel():
    data = body()
    algorithm = data.get('algorithm', ALGORITHMS[0])
    if algorithm not in ALGORITHMS:
        raise ValueError('Thuật toán AEAD không được hỗ trợ')
    with state_lock:
        s = state()
        raw, filename = data_for(s, data)
        result, packet, decoded = chosen_lab(s, data).channel(raw, algorithm, data.get('mode', 'authenticated'))
        s.update(packet=packet, decoded=decoded, decoded_name=filename)
        result.update(download_ciphertext='/api/lab/download/ciphertext',
                      download_plaintext='/api/lab/download/plaintext')
        return jsonify(result)


@bp.get('/api/lab/download/<kind>')
def download(kind):
    with state_lock:
        s = state()
        if 'decoded' not in s:
            raise ValueError('Hãy chạy kênh truyền trước')
        if kind == 'plaintext':
            raw, name, mime = s['decoded'], 'giai_ma_'+s['decoded_name'], 'application/octet-stream'
        elif kind == 'ciphertext':
            raw = json.dumps(s['packet'], ensure_ascii=False, indent=2).encode('utf-8')
            name, mime = 'ban_ma.json', 'application/json'
        else:
            raise ValueError('Loại tệp tải xuống không hợp lệ')
    return send_file(BytesIO(raw), mimetype=mime, as_attachment=True, download_name=name)


@bp.post('/api/toy-dh')
def custom_dh():
    data = body()
    return jsonify(toy_dh(data.get('p', 23), data.get('g', 5), data.get('a', 6), data.get('b', 15)))


@bp.post('/api/kerberos/<action>')
def kerberos(action):
    data = body()
    with state_lock:
        return jsonify(state()['kerberos'].step(action, data.get('password', '')))
