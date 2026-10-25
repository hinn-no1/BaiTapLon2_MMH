import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import serialization

def generate_entity_keys(entity_name: str, algorithm: str) -> dict:
    if algorithm == 'RSA-PSS':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == 'ECDSA':
        private_key = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == 'Ed25519':
        private_key = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Thuật toán {algorithm} không được hỗ trợ.")

    public_key = private_key.public_key()
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    fingerprint = hashlib.sha256(pub_pem).hexdigest()[:32]
    
    return {
        "entity": entity_name,
        "algorithm": algorithm,
        "private_key": private_key,
        "public_key_pem": pub_pem.decode('utf-8'),
        "fingerprint": fingerprint
    }
