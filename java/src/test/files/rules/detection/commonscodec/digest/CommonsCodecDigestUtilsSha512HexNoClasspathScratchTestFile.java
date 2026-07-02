import org.apache.commons.codec.digest.DigestUtils;

public class CommonsCodecDigestUtilsSha512HexNoClasspathScratchTestFile {

    public String hash(String input) {
        return DigestUtils.sha512Hex(input);
    }
}
