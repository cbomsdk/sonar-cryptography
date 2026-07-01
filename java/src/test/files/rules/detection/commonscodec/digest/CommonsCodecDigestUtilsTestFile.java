import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

public class CommonsCodecDigestUtilsTestFile {

    public void test(byte[] data, MessageDigest defaultDigest) {
        DigestUtils.md2(data); // Noncompliant {{(MessageDigest) MD2}}
        DigestUtils.md5Hex("abc"); // Noncompliant {{(MessageDigest) MD5}}
        DigestUtils.sha(data); // Noncompliant {{(MessageDigest) SHA1}}
        DigestUtils.sha1Hex("abc"); // Noncompliant {{(MessageDigest) SHA1}}
        DigestUtils.getDigest("SHA-224"); // Noncompliant {{(MessageDigest) SHA224}}
        DigestUtils.sha256(data); // Noncompliant {{(MessageDigest) SHA256}}
        DigestUtils.sha384Hex("abc"); // Noncompliant {{(MessageDigest) SHA384}}
        DigestUtils.sha512(data); // Noncompliant {{(MessageDigest) SHA512}}
        DigestUtils.sha512_224Hex("abc"); // Noncompliant {{(MessageDigest) SHA512/224}}
        DigestUtils.sha512_256(data); // Noncompliant {{(MessageDigest) SHA512/256}}
        DigestUtils.sha3_224Hex("abc"); // Noncompliant {{(MessageDigest) SHA3-224}}
        DigestUtils.sha3_256(data); // Noncompliant {{(MessageDigest) SHA3-256}}
        DigestUtils.sha3_384Hex("abc"); // Noncompliant {{(MessageDigest) SHA3-384}}
        DigestUtils.sha3_512(data); // Noncompliant {{(MessageDigest) SHA3-512}}
        DigestUtils.getSha512Digest(); // Noncompliant {{(MessageDigest) SHA512}}
        DigestUtils.getDigest("SHA-384", defaultDigest); // Noncompliant {{(MessageDigest) SHA384}}
        new DigestUtils("SHA-512"); // Noncompliant {{(MessageDigest) SHA512}}
    }
}
