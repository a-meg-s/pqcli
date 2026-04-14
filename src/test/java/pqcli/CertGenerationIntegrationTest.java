package pqcli;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Integration tests: generate certs via the internal API and verify structure.
 * No file I/O — tests the generation logic only.
 */
public class CertGenerationIntegrationTest {

    static {
        ProviderSetup.setupProvider();
    }

    // --- Single algorithm certs ---

    @Test
    public void singleRsaCertIsValid() throws Exception {
        X509Certificate cert = makeCert("RSA:3072", "/CN=TestRSA");
        assertEquals("CN=TestRSA", cert.getSubjectX500Principal().getName());
        assertNotNull(cert.getPublicKey());
        assertEquals("RSA", cert.getPublicKey().getAlgorithm());
        assertTrue(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength() >= 3000);
        assertTrue(cert.getNotAfter().after(new Date()));
    }

    @Test
    public void singleMlDsaCertIsValid() throws Exception {
        X509Certificate cert = makeCert("ML-DSA:65", "/CN=TestMLDSA");
        assertEquals("CN=TestMLDSA", cert.getSubjectX500Principal().getName());
        assertTrue("Expected ML-DSA key", cert.getPublicKey().getAlgorithm().startsWith("ML-DSA"));
    }

    @Test
    public void singleSlhDsaCertIsValid() throws Exception {
        X509Certificate cert = makeCert("SLH-DSA:128f", "/CN=TestSLH");
        assertEquals("CN=TestSLH", cert.getSubjectX500Principal().getName());
        // SLH-DSA public key should be present
        assertNotNull(cert.getPublicKey().getEncoded());
    }

    @Test
    public void slhDsaShake128sCertIsValid() throws Exception {
        X509Certificate cert = makeCert("SLH-DSA:shake-128s", "/CN=TestSHAKE128s");
        assertEquals("CN=TestSHAKE128s", cert.getSubjectX500Principal().getName());
        assertNotNull(cert.getPublicKey().getEncoded());
    }

    @Test
    public void slhDsaShake128fCertIsValid() throws Exception {
        X509Certificate cert = makeCert("SLH-DSA:shake-128f", "/CN=TestSHAKE128f");
        assertEquals("CN=TestSHAKE128f", cert.getSubjectX500Principal().getName());
        assertNotNull(cert.getPublicKey().getEncoded());
    }

    @Test
    public void slhDsaShake256sCertIsValid() throws Exception {
        X509Certificate cert = makeCert("SLH-DSA:shake-256s", "/CN=TestSHAKE256s");
        assertEquals("CN=TestSHAKE256s", cert.getSubjectX500Principal().getName());
        assertNotNull(cert.getPublicKey().getEncoded());
    }

    @Test
    public void singleEcCertIsValid() throws Exception {
        X509Certificate cert = makeCert("EC:secp256r1", "/CN=TestEC");
        assertEquals("CN=TestEC", cert.getSubjectX500Principal().getName());
        assertEquals("EC", cert.getPublicKey().getAlgorithm());
    }

    @Test
    public void singleEd25519CertIsValid() throws Exception {
        X509Certificate cert = makeCert("Ed25519", "/CN=TestEd25519");
        assertEquals("CN=TestEd25519", cert.getSubjectX500Principal().getName());
        assertEquals("Ed25519", cert.getPublicKey().getAlgorithm());
    }

    @Test
    public void singleDsaCertIsValid() throws Exception {
        X509Certificate cert = makeCert("DSA:2048", "/CN=TestDSA");
        assertEquals("CN=TestDSA", cert.getSubjectX500Principal().getName());
        assertEquals("DSA", cert.getPublicKey().getAlgorithm());
    }

    @Test
    public void singleEd448CertIsValid() throws Exception {
        X509Certificate cert = makeCert("Ed448", "/CN=TestEd448");
        assertEquals("CN=TestEd448", cert.getSubjectX500Principal().getName());
        assertEquals("Ed448", cert.getPublicKey().getAlgorithm());
    }

    // --- Hybrid cert ---

    @Test
    public void hybridCertHasAltPublicKeyExtension() throws Exception {
        X509Certificate cert = makeCert("RSA:3072,ML-DSA:65", "/CN=Hybrid");
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());

        // SubjectAltPublicKeyInfo extension (OID 2.5.29.72) must be present
        org.bouncycastle.asn1.x509.Extension altKeyExt =
            holder.getExtensions().getExtension(org.bouncycastle.asn1.x509.Extension.subjectAltPublicKeyInfo);
        assertNotNull("SubjectAltPublicKeyInfo extension missing", altKeyExt);

        // AltSignatureAlgorithm extension (OID 2.5.29.73) must be present
        org.bouncycastle.asn1.x509.Extension altSigAlgExt =
            holder.getExtensions().getExtension(org.bouncycastle.asn1.x509.Extension.altSignatureAlgorithm);
        assertNotNull("AltSignatureAlgorithm extension missing", altSigAlgExt);

        // AltSignatureValue extension (OID 2.5.29.74) must be present
        org.bouncycastle.asn1.x509.Extension altSigValExt =
            holder.getExtensions().getExtension(org.bouncycastle.asn1.x509.Extension.altSignatureValue);
        assertNotNull("AltSignatureValue extension missing", altSigValExt);

        // Primary key is RSA
        assertEquals("RSA", cert.getPublicKey().getAlgorithm());
    }

    // --- Composite cert ---

    @Test
    public void compositeCertHasCompositePublicKey() throws Exception {
        X509Certificate cert = makeCert("RSA:3072_ML-DSA:65", "/CN=Composite");
        assertTrue("Expected CompositePublicKey", cert.getPublicKey() instanceof CompositePublicKey);
        CompositePublicKey cpk = (CompositePublicKey) cert.getPublicKey();
        assertEquals(2, cpk.getPublicKeys().size());
        assertEquals("RSA",    cpk.getPublicKeys().get(0).getAlgorithm());
        assertTrue("Expected ML-DSA component", cpk.getPublicKeys().get(1).getAlgorithm().startsWith("ML-DSA"));
    }

    // --- ViewCommand oidToName roundtrip ---

    @Test
    public void oidToNameResolvesKnownOids() {
        assertEquals("RSA",        ViewCommand.oidToName("1.2.840.113549.1.1.1"));
        assertEquals("ML-DSA-65",  ViewCommand.oidToName("2.16.840.1.101.3.4.3.18"));
        assertEquals("ML-DSA-44",  ViewCommand.oidToName("2.16.840.1.101.3.4.3.17"));
        assertEquals("ML-DSA-87",  ViewCommand.oidToName("2.16.840.1.101.3.4.3.19"));
        assertEquals("Ed25519",    ViewCommand.oidToName("1.3.101.112"));
        assertEquals("Key Usage",  ViewCommand.oidToName("2.5.29.15"));
    }

    @Test
    public void oidToNameReturnsOidForUnknown() {
        String unknown = "1.2.3.4.5.99";
        assertEquals(unknown, ViewCommand.oidToName(unknown));
    }

    // --- KeyUsage / extension tests ---

    @Test
    public void selfSignedCertKeyUsageIsCaAppropriate() throws Exception {
        X509Certificate cert = makeCert("RSA:3072", "/CN=TestCA-KU");
        // BasicConstraints CA:true
        assertTrue("Expected CA cert (BasicConstraints pathLen >= 0)", cert.getBasicConstraints() >= 0);
        boolean[] ku = cert.getKeyUsage();
        assertNotNull("KeyUsage extension must be present", ku);
        // [5] = keyCertSign, [6] = cRLSign
        assertTrue("keyCertSign must be set",  ku[5]);
        assertTrue("cRLSign must be set",       ku[6]);
        // [2] = keyEncipherment — must NOT be present for a CA signing cert
        assertFalse("keyEncipherment must not be set", ku[2]);
    }

    @Test
    public void compositeSelfSignedCertVerifies() throws Exception {
        X509Certificate cert = makeCert("RSA:3072_ML-DSA:65", "/CN=CompositeVerify");
        assertTrue("Expected CompositePublicKey", cert.getPublicKey() instanceof CompositePublicKey);
        // primary signature must verify using the composite public key (no exception = pass)
        cert.verify(cert.getPublicKey(), "BC");
    }

    // --- Helpers ---

    private static X509Certificate makeCert(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair altKeyPair = algorithmSet.isHybrid()
            ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms())
            : null;

        // Use reflection to call the private generateCertificate method
        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);

        // Convert OpenSSL-style subject to X.500
        String x500Subject = subject.replace('/', ',').replaceFirst("^,", "");
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, altKeyPair, x500Subject, 1.0);
    }
}
