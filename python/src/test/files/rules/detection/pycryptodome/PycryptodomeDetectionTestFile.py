from Crypto.Cipher import AES
from Crypto.Hash import CMAC, HMAC, SHA256
from Crypto.Protocol.KDF import HKDF, PBKDF2, scrypt
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15, pss
from Cryptodome.Hash import SHA3_256

key = b"0" * 32
iv = b"1" * 16
salt = b"2" * 16

sha256_digest = SHA256.new(data=b"message")  # Noncompliant
sha3_digest = SHA3_256.new(data=b"message")  # Noncompliant

aes_cipher = AES.new(key, AES.MODE_GCM, nonce=iv)  # Noncompliant
aes_cipher.encrypt(b"message")

hmac_value = HMAC.new(key, b"message", SHA256)  # Noncompliant
cmac_value = CMAC.new(key, b"message", ciphermod=AES)  # Noncompliant

pbkdf2_key = PBKDF2(  # Noncompliant
    b"password",
    salt,
    dkLen=32,
    count=480000,
    hmac_hash_module=SHA256,
)
scrypt_key = scrypt(b"password", salt, 32, 16384, 8, 1)  # Noncompliant
hkdf_key = HKDF(key, 32, salt, SHA256)  # Noncompliant

rsa_key = RSA.generate(2048)  # Noncompliant
ecc_key = ECC.generate(curve="P-256")  # Noncompliant

pkcs1_signer = pkcs1_15.new(rsa_key)  # Noncompliant
signature = pkcs1_signer.sign(sha256_digest)

pss_verifier = pss.new(rsa_key.publickey())  # Noncompliant
pss_verifier.verify(sha256_digest, signature)
