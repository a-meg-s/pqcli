package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.Assert.*;

/**
 * Tests for CSR generation: single, composite, and hybrid PKCS#10.
 *
 * Standard PKCS#10 (RFC 2986) supports one primary subjectPublicKeyInfo and one
 * primary outer signature. Composite CSR reuses the standard structure with a
 * composite key; hybrid CSR uses BC's non-standard 3-arg build() path that
 * injects alt-* structures via the PKCS#10 attribute field.
 */
public class CsrCommandTest {

    static {
        ProviderSetup.setupProvider();
    }

    @Test
    public void rsaCsrIsValidPkcs10() throws Exception {
        PKCS10CertificationRequest csr = makeSingleCsr("RSA:3072", "CN=CsrRSA");
        assertEquals("CN=CsrRSA", csr.getSubject().toString());
        assertEquals("RSA", new JcaPEMKeyConverter()
            .setProvider("BC")
            .getPublicKey(csr.getSubjectPublicKeyInfo())
            .getAlgorithm());
    }

    @Test
    public void mlDsaCsrIsValidPkcs10() throws Exception {
        PKCS10CertificationRequest csr = makeSingleCsr("ML-DSA:65", "CN=CsrMLDSA");
        assertEquals("CN=CsrMLDSA", csr.getSubject().toString());
        assertTrue("Expected ML-DSA public key",
            new JcaPEMKeyConverter()
                .setProvider("BC")
                .getPublicKey(csr.getSubjectPublicKeyInfo())
                .getAlgorithm()
                .startsWith("ML-DSA"));
    }

    /**
     * Composite CSR: composite public key encodes into the standard primary
     * subjectPublicKeyInfo. Algorithm identifiers are draft/BC-internal.
     */
    @Test
    public void compositeCsrGeneratesValidPkcs10() throws Exception {
        AlgorithmSet algSet = new AlgorithmSet("RSA:3072_ML-DSA:65");
        KeyPair kp = KeyGenerator.generateKeyPair(algSet.getAlgorithms());
        ContentSigner signer = CertificateGenerator.getSigner(algSet.getAlgorithms(), kp);

        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=CompositeCSR"), kp.getPublic());
        PKCS10CertificationRequest csr = builder.build(signer);

        assertEquals("CN=CompositeCSR", csr.getSubject().toString());

        // The primary subjectPublicKeyInfo must carry a composite public key
        PublicKey pub = new JcaPEMKeyConverter().setProvider("BC")
            .getPublicKey(csr.getSubjectPublicKeyInfo());
        assertTrue("Expected CompositePublicKey in subjectPublicKeyInfo",
            pub instanceof CompositePublicKey);
    }

    /**
     * Hybrid CSR: BC's 3-arg build() injects alt public key and alt signature
     * into the PKCS#10 attribute field. This is BC-specific and not broadly
     * standardized. Verified via hasAltPublicKey() and isAltSignatureValid().
     */
    @Test
    public void hybridCsrContainsAltPublicKeyAndSignature() throws Exception {
        AlgorithmSet algSet = new AlgorithmSet("RSA:3072,ML-DSA:65");
        KeyPair primaryKP = KeyGenerator.generateKeyPair(algSet.getAlgorithms());
        KeyPair altKP = KeyGenerator.generateKeyPair(algSet.getAltAlgorithms());

        ContentSigner primarySigner = CertificateGenerator.getSigner(algSet.getAlgorithms(), primaryKP);
        ContentSigner altSigner = CertificateGenerator.getSigner(algSet.getAltAlgorithms(), altKP);

        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=HybridCSR"), primaryKP.getPublic());
        PKCS10CertificationRequest csr = builder.build(primarySigner, altKP.getPublic(), altSigner);

        assertTrue("Hybrid CSR must have alt public key", csr.hasAltPublicKey());

        ContentVerifierProvider altVerifier = new JcaContentVerifierProviderBuilder()
            .setProvider("BC").build(altKP.getPublic());
        assertTrue("Alt signature must be valid", csr.isAltSignatureValid(altVerifier));
    }

    // --- Helpers ---

    private static PKCS10CertificationRequest makeSingleCsr(String keyAlgo, String subject) throws Exception {
        AlgorithmSet algorithmSet = new AlgorithmSet(keyAlgo);
        KeyPair keyPair = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        String sigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(algorithmSet.getAlgorithms()[0]);

        JcaPKCS10CertificationRequestBuilder builder =
            new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(keyPair.getPrivate());
        return builder.build(signer);
    }
}
