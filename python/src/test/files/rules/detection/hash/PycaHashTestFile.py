from cryptography.hazmat.primitives import hashes

hashes.SHA1() # Noncompliant {{(MessageDigest) SHA1}}
hashes.SHA512_224() # Noncompliant {{(MessageDigest) SHA512/224}}
hashes.SHA512_256() # Noncompliant {{(MessageDigest) SHA512/256}}
hashes.SHA224() # Noncompliant {{(MessageDigest) SHA224}}
hashes.SHA256() # Noncompliant {{(MessageDigest) SHA256}}
hashes.SHA384() # Noncompliant {{(MessageDigest) SHA384}}
hashes.SHA512() # Noncompliant {{(MessageDigest) SHA512}}
hashes.SHA3_224() # Noncompliant {{(MessageDigest) SHA3-224}}
hashes.SHA3_256() # Noncompliant {{(MessageDigest) SHA3-256}}
hashes.SHA3_384() # Noncompliant {{(MessageDigest) SHA3-384}}
hashes.SHA3_512() # Noncompliant {{(MessageDigest) SHA3-512}}
hashes.SHAKE128(32) # Noncompliant {{(ExtendableOutputFunction) SHAKE128}}
hashes.SHAKE256(64) # Noncompliant {{(ExtendableOutputFunction) SHAKE256}}
hashes.MD5() # Noncompliant {{(MessageDigest) MD5}}
hashes.BLAKE2b(64) # Noncompliant {{(MessageDigest) BLAKE2b}}
hashes.BLAKE2s(32) # Noncompliant {{(MessageDigest) BLAKE2s}}
hashes.SM3() # Noncompliant {{(MessageDigest) SM3}}

hasher = hashes.Hash(hashes.SHA512()) # Noncompliant {{(MessageDigest) SHA512}}
hasher.update(b"message")
hasher.finalize()
