package pqcli;

import org.junit.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * Tests for VerifyCommand: primary signature verification via cert.verify().
 */
public class VerifyCommandTest {

    static {
        ProviderSetup.setupProvider();
    }

    @Test
    public void selfSignedRsaVerifies() throws Exception {
        X509Certificate cert = makeCert("RSA:3072", "/CN=VerifyRSA");
        // Should not throw
        cert.verify(cert.getPublicKey(), "BC");
    }

    @Test
    public void selfSignedMlDsaVerifies() throws Exception {
        X509Certificate cert = makeCert("ML-DSA:65", "/CN=VerifyMLDSA");
        cert.verify(cert.getPublicKey(), "BC");
    }

    @Test
    public void hybridCertVerifiesPrimarySignature() throws Exception {
        X509Certificate cert = makeCert("RSA:3072,ML-DSA:65", "/CN=VerifyHybrid");
        // Primary signature is RSA — verify with primary public key
        cert.verify(cert.getPublicKey(), "BC");
        assertEquals("RSA", cert.getPublicKey().getAlgorithm());
    }

    // --- Helper (mirrors CertGenerationIntegrationTest.makeCert) ---

    private static X509Certificate makeCert(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair altKeyPair = algorithmSet.isHybrid()
            ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms())
            : null;

        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);

        String x500Subject = subject.replace('/', ',').replaceFirst("^,", "");
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, altKeyPair, x500Subject, 1.0);
    }
}
