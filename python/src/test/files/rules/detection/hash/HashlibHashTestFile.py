import hashlib

hashlib.sha1(b"message") # Noncompliant {{(MessageDigest) SHA1}}
hashlib.sha256(b"message") # Noncompliant {{(MessageDigest) SHA256}}
hashlib.sha3_256(b"message") # Noncompliant {{(MessageDigest) SHA3-256}}
hashlib.shake_128(b"message") # Noncompliant {{(ExtendableOutputFunction) SHAKE128}}
hashlib.blake2b(b"message") # Noncompliant {{(MessageDigest) BLAKE2b}}
hashlib.md5(b"message") # Noncompliant {{(MessageDigest) MD5}}

hashlib.new("sha512", b"message") # Noncompliant {{(MessageDigest) SHA512}}
hashlib.new("shake_256") # Noncompliant {{(ExtendableOutputFunction) SHAKE256}}
