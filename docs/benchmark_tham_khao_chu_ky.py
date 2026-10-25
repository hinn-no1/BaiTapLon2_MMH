"""Supplementary local reference measurement (cryptography backend, NOT project's PyCryptodome)."""
import os,time,statistics,json,platform
from cryptography.hazmat.primitives.asymmetric import rsa,ec,padding,dh
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
N=20

def summary(f):
 out=[]
 for i in range(N):
  t=time.perf_counter_ns(); f(); out.append((time.perf_counter_ns()-t)/1e6)
 return {'mean_ms':round(statistics.mean(out),5),'median_ms':round(statistics.median(out),5),'min_ms':round(min(out),5),'max_ms':round(max(out),5),'runs':len(out)}

def spec(alg):
 if alg=='RSA-2048': return rsa.generate_private_key(public_exponent=65537,key_size=2048)
 if alg=='RSA-3072': return rsa.generate_private_key(public_exponent=65537,key_size=3072)
 if alg=='ECDSA-P256': return ec.generate_private_key(ec.SECP256R1())

def sign(alg,private,m):
 if alg=='ECDSA-P256':return private.sign(m,ec.ECDSA(hashes.SHA256()))
 return private.sign(m,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

def verify(alg,public,sig,m):
 if alg=='ECDSA-P256':return public.verify(sig,m,ec.ECDSA(hashes.SHA256()))
 return public.verify(sig,m,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

result={'metadata':{'backend':'cryptography (reference only)','runs':N,'python':platform.python_version(),'system':platform.platform(),'timer':'perf_counter_ns','units':'ms'},'signatures':{}}
m=b'BTL2 crypto reference same message'
for alg in ['RSA-2048','RSA-3072','ECDSA-P256']:
 k=spec(alg); p=k.public_key()
 sig=sign(alg,k,m); verify(alg,p,sig,m)
 result['signatures'][alg]={
 'keygen':summary(lambda:spec(alg)),
 'sign':summary(lambda:sign(alg,k,m)),
 'verify':summary(lambda:verify(alg,p,sig,m)),
 'signature_bytes':len(sig),
 'public_key_pem_bytes':len(p.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)),
 'private_key_pem_bytes':len(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 }
 print(alg,result['signatures'][alg],flush=True)
open('/mnt/data/benchmark_reference_signatures.json','w').write(json.dumps(result,ensure_ascii=False,indent=2))
