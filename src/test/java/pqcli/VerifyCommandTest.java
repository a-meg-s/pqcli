package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

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

    /**
     * Hybrid cert: alt signature (ML-DSA-65, OID 2.5.29.74) verified using the
     * BC-specific public API X509CertificateHolder.isAlternativeSignatureValid().
     * Not JCA standard; not standardized X.509 behavior.
     */
    @Test
    public void hybridCertAltSignatureVerifies() throws Exception {
        X509Certificate cert = makeCert("RSA:3072,ML-DSA:65", "/CN=VerifyHybridAlt");
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());

        SubjectAltPublicKeyInfo altKeyInfo = SubjectAltPublicKeyInfo.fromExtensions(
                holder.getExtensions());
        assertNotNull("SubjectAltPublicKeyInfo must be present in hybrid cert", altKeyInfo);

        SubjectPublicKeyInfo altSpki = SubjectPublicKeyInfo.getInstance(altKeyInfo.toASN1Primitive());
        java.security.PublicKey altPublicKey = new JcaPEMKeyConverter()
                .setProvider("BC").getPublicKey(altSpki);
        assertTrue("Alt key should be ML-DSA", altPublicKey.getAlgorithm().startsWith("ML-DSA"));

        ContentVerifierProvider altProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(altPublicKey);

        boolean altValid;
        try {
            altValid = holder.isAlternativeSignatureValid(altProvider);
        } catch (CertException e) {
            fail("Alt signature verification threw CertException: " + e.getMessage());
            return;
        }
        assertTrue("isAlternativeSignatureValid must return true for correct hybrid cert", altValid);
    }

    /**
     * A cert with only OID 2.5.29.72 (SubjectAltPublicKeyInfo) but without OIDs 2.5.29.73/74
     * must be rejected by verify as a malformed hybrid cert.
     */
    @Test
    public void malformedHybridCertFailsVerify() throws Exception {
        // Build a cert with ONLY SubjectAltPublicKeyInfo (no alt sig algo / alt sig value).
        AlgorithmSet primarySet = new AlgorithmSet("RSA:3072");
        java.security.KeyPair primaryPair = KeyGenerator.generateKeyPair(primarySet.getAlgorithms());
        AlgorithmSet altSet = new AlgorithmSet("ML-DSA:65");
        java.security.KeyPair altPair = KeyGenerator.generateKeyPair(altSet.getAlgorithms());

        X500Name name = new X500Name("CN=MalformedHybrid");
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore, notAfter, name, primaryPair.getPublic());

        // Add only OID 2.5.29.72 — intentionally omit 2.5.29.73 and 2.5.29.74.
        // Parse via SubjectPublicKeyInfo first, then use the explicit
        // SubjectAltPublicKeyInfo(SubjectPublicKeyInfo) constructor — mirrors the
        // reverse conversion already used in VerifyCommand and is unambiguous.
        SubjectPublicKeyInfo altSpki = SubjectPublicKeyInfo.getInstance(altPair.getPublic().getEncoded());
        SubjectAltPublicKeyInfo altKeyInfo = new SubjectAltPublicKeyInfo(altSpki);
        builder.addExtension(Extension.subjectAltPublicKeyInfo, false, altKeyInfo);

        ContentSigner signer = CertificateGenerator.getSigner(primarySet.getAlgorithms(), primaryPair);
        X509Certificate malformedCert = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));

        File tempFile = File.createTempFile("malformed_hybrid", ".pem");
        tempFile.deleteOnExit();
        CertificateGenerator.saveCertificateToFile(tempFile.getAbsolutePath(), malformedCert);

        // Capture both stdout and stderr so the test is debuggable if it fails.
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        PrintStream origOut = System.out;
        System.setErr(new PrintStream(errBuf));
        System.setOut(new PrintStream(outBuf));
        int exitCode;
        try {
            exitCode = new CommandLine(new VerifyCommand()).execute("-in", tempFile.getAbsolutePath());
        } finally {
            System.setErr(origErr);
            System.setOut(origOut);
        }

        assertEquals("verify must exit 1 for malformed hybrid cert", 1, exitCode);
        String errOutput = errBuf.toString();
        assertTrue("stderr must contain malformed-extension label; stderr=" + errOutput +
                " stdout=" + outBuf,
                errOutput.contains("Alt Signature:     FAIL: incomplete hybrid extensions"));
    }

    /**
     * Alt signature verification must fail when given a key that did not sign the certificate.
     */
    @Test
    public void hybridCertAltSignatureFailsWithWrongKey() throws Exception {
        X509Certificate cert = makeCert("RSA:3072,ML-DSA:65", "/CN=WrongAltKey");
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());

        // Fresh ML-DSA key — NOT the one used to produce the cert's alt signature.
        java.security.KeyPair wrongPair = KeyGenerator.generateKeyPair(
                new AlgorithmSet("ML-DSA:65").getAlgorithms());
        ContentVerifierProvider wrongProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC").build(wrongPair.getPublic());

        boolean altValid;
        try {
            altValid = holder.isAlternativeSignatureValid(wrongProvider);
        } catch (CertException e) {
            return;  // CertException is an acceptable failure signal.
        }
        assertFalse("Alt signature verification with a wrong key must return false", altValid);
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
