import hashlib

salt = b"saltysalt"

pbkdf2_key = hashlib.pbkdf2_hmac( # Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA256}}
    "sha256",
    b"password",
    salt,
    480000,
    32,
)

scrypt_key = hashlib.scrypt( # Noncompliant {{(PasswordBasedKeyDerivationFunction) SCRYPT}}
    b"password",
    salt=salt,
    n=16384,
    r=8,
    p=1,
    dklen=32,
)
