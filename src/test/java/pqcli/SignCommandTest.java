package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Tests for sign command: issuer matches CA, cert verifies against CA public key.
 */
public class SignCommandTest {

    static {
        ProviderSetup.setupProvider();
    }

    @Test
    public void signedCertHasCaIssuer() throws Exception {
        X509Certificate caCert = makeSelfSignedCa("RSA:3072", "CN=TestCA");
        PKCS10CertificationRequest csr = makeCsr("ML-DSA:65", "CN=TestEE");
        X509Certificate signed = sign(csr, caCert, makeKeyPair("RSA:3072"));

        String issuer = signed.getIssuerX500Principal().getName();
        String caSubject = caCert.getSubjectX500Principal().getName();
        assertEquals("Issuer must equal CA subject", caSubject, issuer);
    }

    @Test
    public void signedCertVerifiesWithCa() throws Exception {
        AlgorithmSet caAlgo = new AlgorithmSet("RSA:3072");
        KeyPair caKeyPair = KeyGenerator.generateKeyPair(caAlgo.getAlgorithms());
        X509Certificate caCert = makeSelfSignedCaWithKey("CN=TestCA2", caKeyPair);

        PKCS10CertificationRequest csr = makeCsr("ML-DSA:65", "CN=TestEE2");
        X509Certificate signed = signWithKey(csr, caCert, caKeyPair);

        // Should not throw
        signed.verify(caCert.getPublicKey(), "BC");
    }

    // --- Helpers ---

    private static KeyPair makeKeyPair(String algo) throws Exception {
        AlgorithmSet as = new AlgorithmSet(algo);
        return KeyGenerator.generateKeyPair(as.getAlgorithms());
    }

    private static X509Certificate makeSelfSignedCa(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());

        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);
        String x500Subject = subject.replace('/', ',').replaceFirst("^,", "");
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, null, x500Subject, 1.0);
    }

    private static X509Certificate makeSelfSignedCaWithKey(String subject, KeyPair keyPair) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet("RSA:3072");
        java.lang.reflect.Method m = CertificateGenerator.class.getDeclaredMethod(
            "generateCertificate",
            AlgorithmSet.class, KeyPair.class, KeyPair.class, String.class, double.class);
        m.setAccessible(true);
        return (X509Certificate) m.invoke(null, algorithmSet, keyPair, null, subject, 1.0);
    }

    private static PKCS10CertificationRequest makeCsr(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        String sigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]);
        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(keyPair.getPrivate());
        return builder.build(signer);
    }

    private static X509Certificate sign(PKCS10CertificationRequest csr, X509Certificate caCert, KeyPair caKeyPair)
            throws Exception {
        return signWithKey(csr, caCert, caKeyPair);
    }

    private static X509Certificate signWithKey(PKCS10CertificationRequest csr, X509Certificate caCert, KeyPair caKeyPair)
            throws Exception {
        String sigAlgo = caCert.getSigAlgName();
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86400000L);
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName("RFC1779"));
        X500Name subject = csr.getSubject();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore, notAfter,
            subject,
            new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().setProvider("BC")
                .getPublicKey(csr.getSubjectPublicKeyInfo())
        );

        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }
}
