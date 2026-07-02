import static org.apache.commons.codec.digest.DigestUtils.sha512Hex;

import java.lang.reflect.Method;
import java.util.function.Function;
import org.apache.commons.codec.digest.DigestUtils;

public class CommonsCodecDigestUtilsSha512HexScratchTestFile {

    public void detected(String input, byte[] bytes) throws Exception {
        DigestUtils.sha512Hex(input); // Noncompliant {{(MessageDigest) SHA512}}
        DigestUtils.sha512Hex(bytes); // Noncompliant {{(MessageDigest) SHA512}}
        org.apache.commons.codec.digest.DigestUtils.sha512Hex(input); // Noncompliant {{(MessageDigest) SHA512}}
        sha512Hex(input); // Noncompliant {{(MessageDigest) SHA512}}
    }

    public void notDetected(String input) throws Exception {
        Function<String, String> reference = DigestUtils::sha512Hex;
        reference.apply(input);

        Method method = DigestUtils.class.getMethod("sha512Hex", String.class);
        method.invoke(null, input);

        FakeDigestUtils.sha512Hex(input);
    }

    static class FakeDigestUtils {
        static String sha512Hex(String input) {
            return input;
        }
    }
}
