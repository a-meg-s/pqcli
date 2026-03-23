package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;

import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * Tests for CSR generation: correct subject and public key in PKCS#10.
 */
public class CsrCommandTest {

    static {
        ProviderSetup.setupProvider();
    }

    @Test
    public void rsaCsrIsValidPkcs10() throws Exception {
        PKCS10CertificationRequest csr = makeCsr("RSA:3072", "CN=CsrRSA");
        assertEquals("CN=CsrRSA", csr.getSubject().toString());
        assertEquals("RSA", new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
            .setProvider("BC")
            .getPublicKey(csr.getSubjectPublicKeyInfo())
            .getAlgorithm());
    }

    @Test
    public void mlDsaCsrIsValidPkcs10() throws Exception {
        PKCS10CertificationRequest csr = makeCsr("ML-DSA:65", "CN=CsrMLDSA");
        assertEquals("CN=CsrMLDSA", csr.getSubject().toString());
        assertTrue("Expected ML-DSA public key",
            new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                .setProvider("BC")
                .getPublicKey(csr.getSubjectPublicKeyInfo())
                .getAlgorithm()
                .startsWith("ML-DSA"));
    }

    // --- Helper ---

    private static PKCS10CertificationRequest makeCsr(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        String sigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]);

        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(keyPair.getPrivate());
        return builder.build(signer);
    }
}
