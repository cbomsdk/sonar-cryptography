from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = rsa.generate_private_key( # Noncompliant {{(PrivateKey) RSA}}
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

def encrypt(message):
    ciphertext = public_key.encrypt( # Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA384(),
            label=None,
        ),
    )
    return ciphertext
