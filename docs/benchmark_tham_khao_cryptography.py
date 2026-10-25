"""Preliminary ONLY using cryptography, not app's required PyCryptodome backend."""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import secrets,time,statistics,json,platform
N=20
p_text='''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'''
p=int(''.join(p_text.split()),16)
assert p.bit_length()==2048

def t(f):
 a=time.perf_counter_ns(); value=f(); return (time.perf_counter_ns()-a)/1e6,value

def meas(f):
 vals=[]
 for _ in range(N):
  ms,_=t(f);vals.append(ms)
 return {'mean_ms':round(statistics.mean(vals),5),'median_ms':round(statistics.median(vals),5),'min_ms':round(min(vals),5),'max_ms':round(max(vals),5)}

def ecdh_keypair():
 return ec.generate_private_key(ec.SECP256R1())

def dh_keypair():
 a=secrets.randbelow((p-1)//2-3)+2
 return a,pow(2,a,p)

sk=ecdh_keypair(); peer=ecdh_keypair().public_key();
a,pub=dh_keypair();b,B=dh_keypair();
assert pow(B,a,p)==pow(pub,b,p)
raw=sk.exchange(ec.ECDH(),peer)
salt=secrets.token_bytes(32)
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=b'toy-app').derive(raw)
plaintext=secrets.token_bytes(1024*1024)
aad=b'{"sender":"Alice","recipient":"Bob","sequence":1}'

def ecdh_agreement():
 raw=sk.exchange(ec.ECDH(),peer)
 return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=b'toy-app').derive(raw)

def aead_measure(aead):
 nonce=secrets.token_bytes(12)
 enc_t,c=t(lambda: aead.encrypt(nonce,plaintext,aad))
 dec_t,p=t(lambda: aead.decrypt(nonce,c,aad))
 assert p==plaintext
 return enc_t,dec_t
out={'description':'REFERENCE ONLY: cryptography backend, not PyCryptodome; n=20',
     'python':platform.python_version(),'os':platform.platform(),
     'ecdh_keygen':meas(ecdh_keypair),'dh2048_keygen':meas(dh_keypair),
     'ecdh_agreement_and_hkdf':meas(ecdh_agreement),
     'dh2048_agreement':meas(lambda:pow(B,a,p))}
for cls,name in ((AESGCM,'AES-256-GCM'),(ChaCha20Poly1305,'ChaCha20-Poly1305')):
 aead=cls(key)
 pairs=[aead_measure(aead) for _ in range(N)]
 out[name]={'encrypt_1MiB':{'mean_ms':round(statistics.mean(x for x,y in pairs),5)},
            'decrypt_1MiB':{'mean_ms':round(statistics.mean(y for x,y in pairs),5)}}
open('/mnt/data/benchmark_tham_khao.json','w').write(json.dumps(out,indent=2))
print(json.dumps(out,indent=2))
