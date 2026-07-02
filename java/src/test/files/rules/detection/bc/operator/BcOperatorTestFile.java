import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PSSParameterSpec;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class BcOperatorTestFile {

    public void testContentSignerBuilder(
            PrivateKey privateKey,
            PublicKey publicKey,
            AlgorithmIdentifier algorithmIdentifier,
            PSSParameterSpec pssParameterSpec)
            throws Exception {
        new JcaContentSignerBuilder("SHA256withRSA"); // Noncompliant {{(Signature) SHA256withRSA}}
        new JcaContentSignerBuilder("SHA384withDSA", publicKey); // Noncompliant {{(Signature) SHA384withDSA}}
        new JcaContentSignerBuilder("SHA3-224withECDSA", algorithmIdentifier); // Noncompliant {{(Signature) SHA3-224withECDSA}}
        new JcaContentSignerBuilder("SHA512withRSA", pssParameterSpec); // Noncompliant {{(Signature) SHA512withRSA}}
        new JcaContentSignerBuilder("SHA256withRSA", pssParameterSpec, algorithmIdentifier); // Noncompliant {{(Signature) SHA256withRSA}}
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey); // Noncompliant {{(Signature) SHA256withRSA}}
    }

    public void testSimpleSignerInfoGeneratorBuilder(
            PrivateKey privateKey,
            X509CertificateHolder certificateHolder,
            X509Certificate certificate,
            byte[] subjectKeyIdentifier)
            throws Exception {
        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder();
        builder.build("SHA256withRSA", privateKey, certificateHolder); // Noncompliant {{(Signature) SHA256withRSA}}
        builder.build("SHA384withDSA", privateKey, certificate); // Noncompliant {{(Signature) SHA384withDSA}}
        builder.build("SHA3-224withECDSA", privateKey, subjectKeyIdentifier); // Noncompliant {{(Signature) SHA3-224withECDSA}}
    }
}
