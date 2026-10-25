"""Minimal AS/TGS/service simulator derived from the supplied Kerberos report.

State belongs to one browser demo session. Replay caches are retained across
new AS requests, and only expire after the ticket itself expires.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

USER, PASSWORD, SERVICE = 'Alice', 'demo123', 'Bob'
TICKET_TTL, CLOCK_SKEW = 120, 30


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(data):
    return base64.b64decode(data, validate=True)


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def password_key(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'kerberos-demo-salt', 100_000)


def seal(key, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(canonical(data))
    return {'nonce': b64(cipher.nonce), 'ciphertext': b64(ciphertext), 'tag': b64(tag)}


def unseal(key, blob):
    try:
        nonce, tag = unb64(blob['nonce']), unb64(blob['tag'])
        if len(nonce) != 12 or len(tag) != 16:
            raise ValueError('invalid size')
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return json.loads(cipher.decrypt_and_verify(unb64(blob['ciphertext']), tag))
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise ValueError('Vé hoặc authenticator đã bị sửa / không hợp lệ') from exc


def require(condition, message):
    if not condition:
        raise ValueError(message)


class KerberosDemo:
    def __init__(self):
        self.k_as_tgs, self.k_tgs_bob = get_random_bytes(32), get_random_bytes(32)
        self.client = {}
        self.seen_tgs, self.seen_service = {}, {}

    @staticmethod
    def use_auth(cache, ticket, authenticator, expires, now):
        for key in list(cache):
            if cache[key] <= now:
                del cache[key]
        fingerprint = hashlib.sha256(canonical([ticket, authenticator])).hexdigest()
        require(fingerprint not in cache, 'Từ chối replay: authenticator đã được sử dụng')
        cache[fingerprint] = expires

    def as_issue(self, password):
        require(isinstance(password, str) and len(password) <= 200, 'Mật khẩu không hợp lệ')
        require(hmac.compare_digest(password.encode('utf-8'), PASSWORD.encode()), 'AS: Sai mật khẩu Alice')
        now, key = int(time.time()), get_random_bytes(32)
        tgt = seal(self.k_as_tgs, {'client': USER, 'k_c_tgs': b64(key),
                                 'issued': now, 'expires': now + TICKET_TTL})
        reply = seal(password_key(password), {'k_c_tgs': b64(key)})
        return tgt, reply

    def make_auth(self, key, now=None):
        return seal(key, {'client': USER, 'timestamp': int(time.time()) if now is None else now,
                          'nonce': secrets.token_hex(16)})

    def tgs_issue(self, tgt, authenticator, now=None):
        now = int(time.time()) if now is None else now
        data = unseal(self.k_as_tgs, tgt)
        require(data['issued'] <= now < data['expires'], 'TGS: TGT đã hết hạn hoặc chưa hiệu lực')
        key = unb64(data['k_c_tgs'])
        auth = unseal(key, authenticator)
        require(auth['client'] == data['client'], 'TGS: Sai danh tính')
        require(abs(now-auth['timestamp']) <= CLOCK_SKEW, 'TGS: Timestamp không hợp lệ')
        self.use_auth(self.seen_tgs, tgt, authenticator, data['expires'], now)
        service_key = get_random_bytes(32)
        expires = min(data['expires'], now + TICKET_TTL)
        ticket = seal(self.k_tgs_bob, {'client': data['client'], 'service': SERVICE,
                                      'k_c_s': b64(service_key), 'issued': now, 'expires': expires})
        reply = seal(key, {'k_c_s': b64(service_key), 'expires': expires})
        return ticket, reply

    def service_accept(self, ticket, authenticator, now=None):
        now = int(time.time()) if now is None else now
        data = unseal(self.k_tgs_bob, ticket)
        require(data['service'] == SERVICE, 'Bob: Vé sai dịch vụ')
        require(data['issued'] <= now < data['expires'], 'Bob: Vé dịch vụ đã hết hạn hoặc chưa hiệu lực')
        auth = unseal(unb64(data['k_c_s']), authenticator)
        require(auth['client'] == data['client'], 'Bob: Sai danh tính')
        require(abs(now-auth['timestamp']) <= CLOCK_SKEW, 'Bob: Timestamp cũ hoặc không hợp lệ')
        self.use_auth(self.seen_service, ticket, authenticator, data['expires'], now)
        return 'Bob: Chấp nhận Alice truy cập dịch vụ'

    def step(self, action, password=''):
        details = {}
        try:
            if action == 'as':
                tgt, reply = self.as_issue(password)
                decoded = unseal(password_key(password), reply)
                self.client = {'tgt': tgt, 'k_c_tgs': unb64(decoded['k_c_tgs'])}
                message = 'AS xác thực Alice và cấp TGT thành công'
                details = {'tgt': tgt, 'encrypted_as_reply': reply,
                           'alice_tgs_key_sha256': hashlib.sha256(self.client['k_c_tgs']).hexdigest()}
            elif action == 'tgs':
                require('tgt' in self.client, 'Hãy xin TGT từ AS trước')
                auth = self.make_auth(self.client['k_c_tgs'])
                ticket, reply = self.tgs_issue(self.client['tgt'], auth)
                decoded = unseal(self.client['k_c_tgs'], reply)
                self.client.update(ticket=ticket, k_c_s=unb64(decoded['k_c_s']), expires=decoded['expires'],
                                   last_tgs_request=(self.client['tgt'], auth))
                self.client.pop('last_request', None)
                message = 'TGS đã cấp vé dịch vụ Bob'
                details = {'service_ticket': ticket, 'encrypted_tgs_reply': reply,
                           'expires': decoded['expires'],
                           'alice_bob_key_sha256': hashlib.sha256(self.client['k_c_s']).hexdigest()}
            elif action == 'service':
                require('ticket' in self.client, 'Hãy xin vé từ TGS trước')
                auth = self.make_auth(self.client['k_c_s'])
                message = self.service_accept(self.client['ticket'], auth)
                self.client['last_request'] = (self.client['ticket'], auth)
                details = {'authenticator': auth, 'ticket_reused': True}
            elif action == 'replay':
                require('last_request' in self.client, 'Hãy truy cập Bob thành công trước')
                message = self.service_accept(*self.client['last_request'])
            elif action == 'replay-tgs':
                require('last_tgs_request' in self.client, 'Hãy xin vé từ TGS trước')
                self.tgs_issue(*self.client['last_tgs_request'])
                message = 'TGS chấp nhận'
            elif action in ('expired', 'stale'):
                require('ticket' in self.client, 'Hãy xin vé từ TGS trước')
                if action == 'expired':
                    now = self.client['expires'] + 1
                    auth = self.make_auth(self.client['k_c_s'], now)
                    details = {'simulation': 'Dịch thời gian kiểm tra vượt hạn vé; không sửa đồng hồ máy.'}
                else:
                    now = int(time.time())
                    auth = self.make_auth(self.client['k_c_s'], now-CLOCK_SKEW-1)
                message = self.service_accept(self.client['ticket'], auth, now=now)
            else:
                raise ValueError('Chức năng Kerberos không tồn tại')
            return {'ok': True, 'action': action, 'message': message, **details}
        except (ValueError, KeyError, TypeError) as exc:
            return {'ok': False, 'action': action, 'message': str(exc), **details}
