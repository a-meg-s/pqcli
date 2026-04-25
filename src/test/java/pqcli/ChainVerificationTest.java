package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.BeforeClass;
import org.junit.Test;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Integration tests for full 3-tier chain generation and verification.
 * Covers all four modes: normal/classical, pure PQC, composite, and hybrid.
 */
public class ChainVerificationTest {

    static {
        ProviderSetup.setupProvider();
    }

    // -------------------------------------------------------------------------
    // Shared fixtures built once per test class
    // -------------------------------------------------------------------------

    // Classical chain: RSA root -> EC intermediate -> RSA leaf
    private static X509Certificate classicalRoot;
    private static KeyPair          classicalRootKp;
    private static X509Certificate classicalIntermediate;
    private static KeyPair          classicalIntKp;
    private static X509Certificate classicalLeaf;

    // ML-DSA chain
    private static X509Certificate mlDsaRoot;
    private static KeyPair          mlDsaRootKp;
    private static X509Certificate mlDsaIntermediate;
    private static KeyPair          mlDsaIntKp;
    private static X509Certificate mlDsaLeaf;

    // Composite chain: MLDSA65-RSA3072-PSS-SHA512 throughout
    private static X509Certificate compositeRoot;
    private static KeyPair          compositeRootKp;
    private static X509Certificate compositeIntermediate;
    private static KeyPair          compositeIntKp;
    private static X509Certificate compositeLeaf;

    // Hybrid chain: RSA+ML-DSA throughout
    private static X509Certificate hybridRoot;
    private static KeyPair          hybridRootPrimaryKp;
    private static KeyPair          hybridRootAltKp;
    private static X509Certificate hybridIntermediate;
    private static KeyPair          hybridIntPrimaryKp;
    private static KeyPair          hybridIntAltKp;
    private static X509Certificate hybridLeaf;

    @BeforeClass
    public static void buildChainFixtures() throws Exception {
        // --- Classical RSA -> EC -> RSA ---
        classicalRootKp = kp("RSA:3072");
        classicalRoot   = selfSignedCa("CN=Classical-Root", "RSA:3072", classicalRootKp);
        classicalIntKp  = kp("EC:secp256r1");
        classicalIntermediate = signCsr(
                buildCsr("CN=Classical-Int", "EC:secp256r1", classicalIntKp),
                classicalRoot, classicalRootKp.getPrivate(), null, "intermediate-ca", -1);
        KeyPair leafKp = kp("RSA:2048");
        classicalLeaf = signCsr(
                buildCsr("CN=Classical-Leaf", "RSA:2048", leafKp),
                classicalIntermediate, classicalIntKp.getPrivate(), null, "leaf", -1);

        // --- ML-DSA ---
        mlDsaRootKp = kp("ML-DSA:65");
        mlDsaRoot   = selfSignedCa("CN=MLDSA-Root", "ML-DSA:65", mlDsaRootKp);
        mlDsaIntKp  = kp("ML-DSA:65");
        mlDsaIntermediate = signCsr(
                buildCsr("CN=MLDSA-Int", "ML-DSA:65", mlDsaIntKp),
                mlDsaRoot, mlDsaRootKp.getPrivate(), null, "intermediate-ca", -1);
        KeyPair mlLeafKp = kp("ML-DSA:44");
        mlDsaLeaf = signCsr(
                buildCsr("CN=MLDSA-Leaf", "ML-DSA:44", mlLeafKp),
                mlDsaIntermediate, mlDsaIntKp.getPrivate(), null, "leaf", -1);

        // --- Composite ---
        compositeRootKp = kp("RSA:3072_ML-DSA:65");
        compositeRoot   = selfSignedCa("CN=Composite-Root", "RSA:3072_ML-DSA:65", compositeRootKp);
        compositeIntKp  = kp("RSA:3072_ML-DSA:65");
        compositeIntermediate = signCsr(
                buildCsr("CN=Composite-Int", "RSA:3072_ML-DSA:65", compositeIntKp),
                compositeRoot, compositeRootKp.getPrivate(), null, "intermediate-ca", -1);
        KeyPair compLeafKp = kp("RSA:3072_ML-DSA:65");
        compositeLeaf = signCsr(
                buildCsr("CN=Composite-Leaf", "RSA:3072_ML-DSA:65", compLeafKp),
                compositeIntermediate, compositeIntKp.getPrivate(), null, "leaf", -1);

        // --- Hybrid ---
        hybridRootPrimaryKp = kp("RSA:3072");
        hybridRootAltKp     = kp("ML-DSA:65");
        hybridRoot = selfSignedHybridCa("CN=Hybrid-Root", hybridRootPrimaryKp, hybridRootAltKp);

        hybridIntPrimaryKp = kp("RSA:3072");
        hybridIntAltKp     = kp("ML-DSA:65");
        PKCS10CertificationRequest hybridIntCsr = buildHybridCsr("CN=Hybrid-Int",
                hybridIntPrimaryKp, hybridIntAltKp);
        hybridIntermediate = signHybridCsr(hybridIntCsr,
                hybridRoot, hybridRootPrimaryKp.getPrivate(), hybridRootAltKp.getPrivate(),
                "intermediate-ca", -1);

        KeyPair hybridLeafPrimaryKp = kp("RSA:3072");
        KeyPair hybridLeafAltKp     = kp("ML-DSA:65");
        PKCS10CertificationRequest hybridLeafCsr = buildHybridCsr("CN=Hybrid-Leaf",
                hybridLeafPrimaryKp, hybridLeafAltKp);
        hybridLeaf = signHybridCsr(hybridLeafCsr,
                hybridIntermediate, hybridIntPrimaryKp.getPrivate(), hybridIntAltKp.getPrivate(),
                "leaf", -1);
    }

    // =========================================================================
    // Positive tests — full 3-tier chains
    // =========================================================================

    @Test
    public void classicalRsaChainVerifies() throws Exception {
        assertEquals(0, runVerifyChain(classicalLeaf, classicalIntermediate, classicalRoot));
    }

    @Test
    public void pqcMlDsaChainVerifies() throws Exception {
        assertEquals(0, runVerifyChain(mlDsaLeaf, mlDsaIntermediate, mlDsaRoot));
    }

    @Test
    public void pqcSlhDsaChainVerifies() throws Exception {
        // SLH-DSA 3-tier chain — fast variant for test speed
        KeyPair rootKp = kp("SLH-DSA:128f");
        X509Certificate root = selfSignedCa("CN=SLHDSA-Root", "SLH-DSA:128f", rootKp);
        KeyPair intKp = kp("SLH-DSA:128f");
        X509Certificate intermediate = signCsr(
                buildCsr("CN=SLHDSA-Int", "SLH-DSA:128f", intKp),
                root, rootKp.getPrivate(), null, "intermediate-ca", -1);
        KeyPair leafKp = kp("SLH-DSA:128f");
        X509Certificate leaf = signCsr(
                buildCsr("CN=SLHDSA-Leaf", "SLH-DSA:128f", leafKp),
                intermediate, intKp.getPrivate(), null, "leaf", -1);
        assertEquals(0, runVerifyChain(leaf, intermediate, root));
    }

    @Test
    public void compositeChainVerifies() throws Exception {
        assertEquals(0, runVerifyChain(compositeLeaf, compositeIntermediate, compositeRoot));
    }

    @Test
    public void compositeChainHasSkidAkid() throws Exception {
        // Every cert in the composite chain must have SKID and AKID
        for (X509Certificate cert : new X509Certificate[]{compositeRoot, compositeIntermediate, compositeLeaf}) {
            assertNotNull("SKID missing in " + cert.getSubjectX500Principal().getName(),
                    cert.getExtensionValue("2.5.29.14"));
            assertNotNull("AKID missing in " + cert.getSubjectX500Principal().getName(),
                    cert.getExtensionValue("2.5.29.35"));
        }
    }

    @Test
    public void hybridChainVerifies() throws Exception {
        assertEquals(0, runVerifyChain(hybridLeaf, hybridIntermediate, hybridRoot));
    }

    @Test
    public void hybridCaIssuingNonHybridLeaf() throws Exception {
        // Hybrid CA issues a non-hybrid (classical RSA) leaf — primary sig only on leaf
        KeyPair nonHybridLeafKp = kp("RSA:3072");
        X509Certificate nonHybridLeaf = signCsr(
                buildCsr("CN=NonHybridLeaf", "RSA:3072", nonHybridLeafKp),
                hybridIntermediate, hybridIntPrimaryKp.getPrivate(), null, "leaf", -1);
        // Leaf should have no hybrid extensions
        X509CertificateHolder holder = new X509CertificateHolder(nonHybridLeaf.getEncoded());
        assertNull("Non-hybrid leaf must not have AltSignatureValue",
                holder.getExtensions().getExtension(Extension.altSignatureValue));
        // Chain verify: leaf is non-hybrid, intermediate is hybrid — mixed mode
        assertEquals(0, runVerifyChain(nonHybridLeaf, hybridIntermediate, hybridRoot));
    }

    @Test
    public void mixedClassicalRootPqcChain() throws Exception {
        KeyPair classicRootKp = kp("RSA:3072");
        X509Certificate classicRoot = selfSignedCa("CN=Classic-Root", "RSA:3072", classicRootKp);
        KeyPair pqcIntKp = kp("ML-DSA:65");
        X509Certificate pqcInt = signCsr(
                buildCsr("CN=PQC-Int", "ML-DSA:65", pqcIntKp),
                classicRoot, classicRootKp.getPrivate(), null, "intermediate-ca", -1);
        KeyPair pqcLeafKp = kp("ML-DSA:65");
        X509Certificate pqcLeaf = signCsr(
                buildCsr("CN=PQC-Leaf", "ML-DSA:65", pqcLeafKp),
                pqcInt, pqcIntKp.getPrivate(), null, "leaf", -1);
        assertEquals(0, runVerifyChain(pqcLeaf, pqcInt, classicRoot));
    }

    @Test
    public void compositeRootClassicalLeaf() throws Exception {
        KeyPair compositeRootKp2 = kp("RSA:3072_ML-DSA:65");
        X509Certificate compositeRoot2 = selfSignedCa("CN=Comp-Root2", "RSA:3072_ML-DSA:65", compositeRootKp2);
        KeyPair compIntKp2 = kp("RSA:3072_ML-DSA:65");
        X509Certificate compInt2 = signCsr(
                buildCsr("CN=Comp-Int2", "RSA:3072_ML-DSA:65", compIntKp2),
                compositeRoot2, compositeRootKp2.getPrivate(), null, "intermediate-ca", -1);
        KeyPair classicalLeafKp = kp("RSA:3072");
        X509Certificate classicalLeaf2 = signCsr(
                buildCsr("CN=Classical-Leaf2", "RSA:3072", classicalLeafKp),
                compInt2, compIntKp2.getPrivate(), null, "leaf", -1);
        assertEquals(0, runVerifyChain(classicalLeaf2, compInt2, compositeRoot2));
    }

    // =========================================================================
    // Positive tests — existing behavior preserved
    // =========================================================================

    @Test
    public void existingOneLinkVerifyStillWorks() throws Exception {
        // Mode A: -in leaf -CAfile intermediate — signature only, no semantic checks
        File leafFile = writeCertFile(classicalLeaf);
        File intFile  = writeCertFile(classicalIntermediate);
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in", leafFile.getAbsolutePath(),
                "-CAfile", intFile.getAbsolutePath());
        assertEquals("Mode A one-link verify must return 0", 0, exitCode);
    }

    @Test
    public void existingSelfSignedVerifyStillWorks() throws Exception {
        File f = writeCertFile(classicalRoot);
        int exitCode = new CommandLine(new VerifyCommand()).execute("-in", f.getAbsolutePath());
        assertEquals("Self-signed verify must return 0", 0, exitCode);
    }

    @Test
    public void intermediateCaProfileIssuance() throws Exception {
        // Issued intermediate must have CA=true, keyCertSign, SKID, AKID
        assertTrue("Intermediate must be CA", classicalIntermediate.getBasicConstraints() >= 0);
        boolean[] ku = classicalIntermediate.getKeyUsage();
        assertNotNull(ku);
        assertTrue("keyCertSign must be set", ku[5]);
        assertNotNull("SKID must be present", classicalIntermediate.getExtensionValue("2.5.29.14"));
        assertNotNull("AKID must be present", classicalIntermediate.getExtensionValue("2.5.29.35"));
    }

    @Test
    public void leafProfileSkidAkidPresent() throws Exception {
        assertEquals("Leaf must have CA=false", -1, classicalLeaf.getBasicConstraints());
        assertNotNull("SKID must be present on leaf", classicalLeaf.getExtensionValue("2.5.29.14"));
        assertNotNull("AKID must be present on leaf", classicalLeaf.getExtensionValue("2.5.29.35"));
    }

    @Test
    public void rootCaSkidAkidPresent() throws Exception {
        assertNotNull("SKID must be present on root CA", classicalRoot.getExtensionValue("2.5.29.14"));
        assertNotNull("AKID must be present on root CA", classicalRoot.getExtensionValue("2.5.29.35"));
    }

    @Test
    public void intermediatePathLenZeroWithLeafIsValid() throws Exception {
        // intermediate with pathLen=0: only a leaf may follow — this is valid
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=PathLenRoot", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:3072");
        X509Certificate intermediate = signCsr(
                buildCsr("CN=PathLenInt", "RSA:3072", intKp),
                root, rootKp.getPrivate(), null, "intermediate-ca", 0); // pathLen=0
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate leaf = signCsr(
                buildCsr("CN=PathLenLeaf", "RSA:3072", leafKp),
                intermediate, intKp.getPrivate(), null, "leaf", -1);
        // Verify intermediate has pathLen=0
        assertEquals("intermediate pathLen must be 0", 0, intermediate.getBasicConstraints());
        // Chain must pass: leaf below intermediate with pathLen=0 is valid
        assertEquals(0, runVerifyChain(leaf, intermediate, root));
    }

    @Test
    public void strongSerialGenerated() {
        for (X509Certificate cert : new X509Certificate[]{
                classicalRoot, classicalIntermediate, classicalLeaf,
                mlDsaRoot, mlDsaIntermediate}) {
            BigInteger s = cert.getSerialNumber();
            String who = cert.getSubjectX500Principal().getName();
            assertTrue(who + ": serial must be positive (signum > 0)", s.signum() > 0);
            assertNotEquals(who + ": serial must not be zero", java.math.BigInteger.ZERO, s);
            assertTrue(who + ": serial DER encoding must be ≤ 20 octets", s.toByteArray().length <= 20);
        }
    }

    // =========================================================================
    // Negative tests
    // =========================================================================

    @Test
    public void wrongIntermediateFails() throws Exception {
        // Leaf signed by classicalRoot directly, but we present classicalIntermediate as intermediate
        KeyPair wrongIntKp = kp("EC:secp256r1");
        X509Certificate wrongLeaf = signCsr(
                buildCsr("CN=WrongLeaf", "EC:secp256r1", wrongIntKp),
                classicalRoot, classicalRootKp.getPrivate(), null, "leaf", -1);
        // wrongLeaf is signed by root, but we claim classicalIntermediate is the intermediate
        assertEquals(1, runVerifyChain(wrongLeaf, classicalIntermediate, classicalRoot));
    }

    @Test
    public void wrongTrustAnchorFails() throws Exception {
        // classicalIntermediate was signed by classicalRoot, but we present mlDsaRoot as trust
        assertEquals(1, runVerifyChain(classicalLeaf, classicalIntermediate, mlDsaRoot));
    }

    @Test
    public void expiredIntermediateFails() throws Exception {
        // Build an expired intermediate
        KeyPair expIntKp = kp("RSA:3072");
        X509Certificate expiredInt = buildExpiredCert("CN=Expired-Int", expIntKp,
                classicalRoot, classicalRootKp, true); // CA=true
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate leaf = signCsr(
                buildCsr("CN=Leaf-ExpInt", "RSA:3072", leafKp),
                expiredInt, expIntKp.getPrivate(), null, "leaf", -1);
        assertEquals(1, runVerifyChain(leaf, expiredInt, classicalRoot));
    }

    @Test
    public void expiredLeafFails() throws Exception {
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate expiredLeaf = buildExpiredCert("CN=Expired-Leaf", leafKp,
                classicalIntermediate, classicalIntKp, false); // CA=false
        assertEquals(1, runVerifyChain(expiredLeaf, classicalIntermediate, classicalRoot));
    }

    @Test
    public void intermediateWithCaFalseFails() throws Exception {
        // Force an intermediate cert with CA=false
        KeyPair intKp = kp("RSA:3072");
        X509Certificate leafProfileInt = signCsr(
                buildCsr("CN=FalseCaInt", "RSA:3072", intKp),
                classicalRoot, classicalRootKp.getPrivate(), null, "leaf", -1); // leaf profile = CA=false
        KeyPair leafKp = kp("RSA:3072");
        // Direct sign: use leafProfileInt as issuer — note: this bypasses issuer CA check via internal helper
        X509Certificate leaf = buildCertWithIssuer("CN=LeafAfterFalseCaInt", leafKp,
                leafProfileInt, intKp, false);
        assertEquals(1, runVerifyChain(leaf, leafProfileInt, classicalRoot));
    }

    @Test
    public void intermediateMissingKeyCertSignFails() throws Exception {
        // Build intermediate with CA=true but KeyUsage only digitalSignature (no keyCertSign)
        KeyPair intKp = kp("RSA:3072");
        X509Certificate badKuInt = buildCertWithCustomKu("CN=BadKuInt", intKp,
                classicalRoot, classicalRootKp, true, KeyUsage.digitalSignature);
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate leaf = buildCertWithIssuer("CN=LeafBadKu", leafKp, badKuInt, intKp, false);
        assertEquals(1, runVerifyChain(leaf, badKuInt, classicalRoot));
    }

    @Test
    public void leafWithCaTrueFailsChain() throws Exception {
        // Force a leaf cert with CA=true — hard error in chain verification
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate caLeaf = buildCertWithIssuer("CN=CaLeaf", leafKp,
                classicalIntermediate, classicalIntKp, true); // CA=true
        assertEquals(1, runVerifyChain(caLeaf, classicalIntermediate, classicalRoot));
    }

    @Test
    public void rootPathLenZeroWithIntermediateFails() throws Exception {
        // Root with pathLen=0 cannot be followed by an intermediate CA
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate rootPathLen0 = buildSelfSignedCaWithPathLen("CN=Root-PL0", rootKp, 0);
        KeyPair intKp = kp("RSA:3072");
        // Bypass SignCommand issuer validation by using internal helper
        X509Certificate intermediate = buildCertWithCustomBc("CN=Int-PL0", intKp,
                rootPathLen0, rootKp, new BasicConstraints(true));
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate leaf = buildCertWithIssuer("CN=Leaf-PL0", leafKp, intermediate, intKp, false);
        assertEquals(1, runVerifyChain(leaf, intermediate, rootPathLen0));
    }

    @Test
    public void missingChainFails() throws Exception {
        // Providing -trust without -chain should fail
        File leafFile  = writeCertFile(classicalLeaf);
        File trustFile = writeCertFile(classicalRoot);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(err));
        int exitCode;
        try {
            exitCode = new CommandLine(new VerifyCommand()).execute(
                    "-in", leafFile.getAbsolutePath(),
                    "-trust", trustFile.getAbsolutePath());
        } finally {
            System.setErr(origErr);
        }
        assertEquals(1, exitCode);
    }

    @Test
    public void cafileConflictWithChainFails() throws Exception {
        File f1 = writeCertFile(classicalLeaf);
        File f2 = writeCertFile(classicalIntermediate);
        File f3 = writeCertFile(classicalRoot);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(err));
        int exitCode;
        try {
            exitCode = new CommandLine(new VerifyCommand()).execute(
                    "-in", f1.getAbsolutePath(),
                    "-CAfile", f2.getAbsolutePath(),
                    "-chain",  f2.getAbsolutePath(),
                    "-trust",  f3.getAbsolutePath());
        } finally {
            System.setErr(origErr);
        }
        assertEquals(1, exitCode);
        assertTrue(err.toString().contains("cannot be combined"));
    }

    @Test
    public void hybridChainMissingAltExtFails() throws Exception {
        // Build a cert with only SubjectAltPublicKeyInfo (missing AltSignatureAlgorithm + AltSignatureValue)
        KeyPair leafKp = kp("RSA:3072");
        KeyPair altKp  = kp("ML-DSA:65");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(hybridIntermediate.getSubjectX500Principal().getName("RFC1779")),
                new BigInteger(128, new java.security.SecureRandom()),
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=MalformedHybridLeaf"),
                leafKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        // Add only SubjectAltPublicKeyInfo — intentionally omit AltSignatureAlgorithm and AltSignatureValue
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo altSpki =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(altKp.getPublic().getEncoded());
        builder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new SubjectAltPublicKeyInfo(altSpki));
        ContentSigner signer = CertificateGenerator.getSigner(
                new AlgorithmSet(hybridIntermediate.getSigAlgName().contains("RSA") ? "RSA:3072" : "ML-DSA:65")
                        .getAlgorithms(), leafKp); // simplified: just sign with leaf primary key
        // Use hybridIntermediate's algorithm for the signer
        ContentSigner intSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                hybridIntermediate.getSigAlgName()).setProvider("BC").build(hybridIntPrimaryKp.getPrivate());
        X509CertificateHolder certHolder = builder.build(intSigner);
        X509Certificate malformed = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        assertEquals(1, runVerifyChain(malformed, hybridIntermediate, hybridRoot));
    }

    @Test
    public void hybridChainWrongAltKeyFails() throws Exception {
        // Verify chain with a hybrid intermediate where we tamper nothing but run chain verify —
        // test passes normally. Now swap hybridIntermediate with a freshly issued hybrid intermediate
        // whose alt key was signed by a DIFFERENT alt key than hybridRoot's alt key.
        // We simulate this by building a hybrid intermediate with a different CA alt key.
        KeyPair wrongAltKp = kp("ML-DSA:65"); // different from hybridRootAltKp
        KeyPair intPrimary = kp("RSA:3072");
        KeyPair intAlt     = kp("ML-DSA:65");

        // Build hybrid int CSR
        PKCS10CertificationRequest csr = buildHybridCsr("CN=WrongAltInt", intPrimary, intAlt);

        // Sign using hybridRoot primary key but wrongAltKp (doesn't match hybridRoot's alt key in cert)
        // This requires bypassing SignCommand's CA alt key validation — build directly
        X509Certificate wrongAltInt = buildHybridCertDirect(csr, hybridRoot, hybridRootPrimaryKp, wrongAltKp, true);

        KeyPair leafPrimary = kp("RSA:3072");
        KeyPair leafAlt     = kp("ML-DSA:65");
        PKCS10CertificationRequest leafCsr = buildHybridCsr("CN=WrongAltLeaf", leafPrimary, leafAlt);
        X509Certificate leaf = buildHybridCertDirect(leafCsr, wrongAltInt, intPrimary, intAlt, false);

        // Chain verification must fail: wrongAltInt's alt sig was produced with wrongAltKp,
        // but hybridRoot cert has hybridRootAltKp in SubjectAltPublicKeyInfo -> mismatch
        assertEquals(1, runVerifyChain(leaf, wrongAltInt, hybridRoot));
    }

    @Test
    public void pathLenWithLeafProfileFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=Root", "RSA:3072", rootKp);
        PKCS10CertificationRequest csr = buildCsr("CN=Leaf", "RSA:3072", kp("RSA:3072"));
        File rootCert = writeCertFile(root);
        File rootKey  = writeKeyFile(rootKp.getPrivate());
        File csrFile  = writeCsrFile(csr);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(err));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr", csrFile.getAbsolutePath(),
                    "-CAcert", rootCert.getAbsolutePath(),
                    "-CAkey",  rootKey.getAbsolutePath(),
                    "--profile", "leaf",
                    "--path-len", "0");
        } finally {
            System.setErr(origErr);
        }
        assertEquals(1, exitCode);
        assertTrue(err.toString().contains("--path-len"));
    }

    @Test
    public void issuerNotCaFails() throws Exception {
        // Try to sign a CSR with an issuer cert that has CA=false
        KeyPair leafKp = kp("RSA:3072");
        // Use classicalLeaf (which has CA=false) as the issuer
        PKCS10CertificationRequest csr = buildCsr("CN=Subject", "RSA:3072", kp("RSA:3072"));
        File issuerCert = writeCertFile(classicalLeaf); // CA=false
        File issuerKey  = writeKeyFile(leafKp.getPrivate());
        File csrFile    = writeCsrFile(csr);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(err));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr", csrFile.getAbsolutePath(),
                    "-CAcert", issuerCert.getAbsolutePath(),
                    "-CAkey",  issuerKey.getAbsolutePath());
        } finally {
            System.setErr(origErr);
        }
        assertEquals(1, exitCode);
        assertTrue(err.toString().contains("CA=true required") || err.toString().contains("not a CA"));
    }

    @Test
    public void issuerMissingKeyCertSignFails() throws Exception {
        // Build a CA cert (CA=true) without keyCertSign in KeyUsage
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate noKcsCert = buildCertWithCustomKu("CN=NoKCS", rootKp,
                classicalRoot, classicalRootKp, true, KeyUsage.digitalSignature);
        PKCS10CertificationRequest csr = buildCsr("CN=Subject", "RSA:3072", kp("RSA:3072"));
        File issuerCert = writeCertFile(noKcsCert);
        File issuerKey  = writeKeyFile(rootKp.getPrivate());
        File csrFile    = writeCsrFile(csr);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream origErr = System.err;
        System.setErr(new PrintStream(err));
        int exitCode;
        try {
            exitCode = new CommandLine(new SignCommand()).execute(
                    "-csr", csrFile.getAbsolutePath(),
                    "-CAcert", issuerCert.getAbsolutePath(),
                    "-CAkey",  issuerKey.getAbsolutePath());
        } finally {
            System.setErr(origErr);
        }
        assertEquals(1, exitCode);
        assertTrue(err.toString().contains("keyCertSign") || err.toString().contains("does not allow"));
    }

    @Test
    public void compositeChainNegative() throws Exception {
        // Tamper: present compositeLeaf with compositeRoot as trust — intermediate mismatch
        assertEquals(1, runVerifyChain(compositeLeaf, compositeRoot, classicalRoot));
    }

    @Test
    public void nonHybridCsrWithHybridCaSucceedsOnPrimaryOnly() throws Exception {
        // Non-hybrid CSR + hybrid CA -> primary sig only on issued cert (no alt extensions on leaf)
        KeyPair nonHybridKp = kp("RSA:3072");
        X509Certificate nonHybridLeaf = signCsr(
                buildCsr("CN=NonHybrid", "RSA:3072", nonHybridKp),
                hybridRoot, hybridRootPrimaryKp.getPrivate(), null, "leaf", -1);
        // Leaf must have no hybrid extensions
        assertNull("Non-hybrid leaf must not have AltSignatureValue",
                new X509CertificateHolder(nonHybridLeaf.getEncoded())
                        .getExtensions().getExtension(Extension.altSignatureValue));
        // Non-hybrid leaf signed by hybrid root verifies in one-link mode
        nonHybridLeaf.verify(hybridRoot.getPublicKey(), "BC"); // no exception = pass
    }

    @Test
    public void akidSkidMismatchFails() throws Exception {
        // Build a cert where AKID does not match issuer SKID
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=AKID-Root", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:3072");
        // Build intermediate with a tampered AKID (using a random key's SKID instead of root's)
        KeyPair foreignKp = kp("RSA:2048");
        X509Certificate intermediate = buildCertWithForeignAkid("CN=AKID-Int", intKp,
                root, rootKp, foreignKp);
        KeyPair leafKp = kp("RSA:3072");
        X509Certificate leaf = signCsr(
                buildCsr("CN=AKID-Leaf", "RSA:3072", leafKp),
                intermediate, intKp.getPrivate(), null, "leaf", -1);
        assertEquals(1, runVerifyChain(leaf, intermediate, root));
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static KeyPair kp(String algo) throws Exception {
        AlgorithmSet as = new AlgorithmSet(algo);
        return KeyGenerator.generateKeyPair(as.getAlgorithms());
    }

    private static X509Certificate selfSignedCa(String subject, String algo, KeyPair kp) throws Exception {
        AlgorithmSet as = new AlgorithmSet(algo);
        return CertificateGenerator.generateCertificate(as, kp, null, subject, 1.0);
    }

    private static X509Certificate selfSignedHybridCa(String subject, KeyPair primary, KeyPair alt) throws Exception {
        AlgorithmSet as = new AlgorithmSet("RSA:3072,ML-DSA:65");
        return CertificateGenerator.generateCertificate(as, primary, alt, subject, 1.0);
    }

    private static PKCS10CertificationRequest buildCsr(String subject, String algo, KeyPair kp) throws Exception {
        AlgorithmSet as = new AlgorithmSet(algo);
        // getSigner handles both single-algo and composite (named combo) cases
        ContentSigner signer = CertificateGenerator.getSigner(as.getAlgorithms(), kp);
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), kp.getPublic())
                .build(signer);
    }

    private static PKCS10CertificationRequest buildHybridCsr(String subject, KeyPair primary, KeyPair alt)
            throws Exception {
        String primarySigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("RSA:3072,ML-DSA:65").getAlgorithms()[0]);
        String altSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("RSA:3072,ML-DSA:65").getAltAlgorithms()[0]);
        ContentSigner primarySigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(primarySigAlgo)
                .setProvider("BC").build(primary.getPrivate());
        ContentSigner altSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(altSigAlgo)
                .setProvider("BC").build(alt.getPrivate());
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), primary.getPublic())
                .build(primarySigner, alt.getPublic(), altSigner);
    }

    private static X509Certificate signCsr(PKCS10CertificationRequest csr,
                                           X509Certificate issuerCert, java.security.PrivateKey issuerKey,
                                           java.security.PrivateKey issuerAltKey,
                                           String profile, int pathLen) throws Exception {
        File issuerCertFile = writeCertFile(issuerCert);
        File issuerKeyFile  = writeKeyFile(issuerKey);
        File csrFile        = writeCsrFile(csr);
        File outDir         = Files.createTempDirectory("pqcli_chain").toFile();
        String outPrefix    = new File(outDir, "out").getAbsolutePath();

        java.util.List<String> args = new java.util.ArrayList<>(java.util.Arrays.asList(
                "-csr",    csrFile.getAbsolutePath(),
                "-CAcert", issuerCertFile.getAbsolutePath(),
                "-CAkey",  issuerKeyFile.getAbsolutePath(),
                "--profile", profile,
                "-out",    outPrefix));
        if (pathLen >= 0) { args.add("--path-len"); args.add(String.valueOf(pathLen)); }
        if (issuerAltKey != null) {
            File altKeyFile = writeKeyFile(issuerAltKey);
            args.add("-CAaltkey"); args.add(altKeyFile.getAbsolutePath());
        }

        int exitCode = new CommandLine(new SignCommand()).execute(args.toArray(new String[0]));
        if (exitCode != 0) throw new RuntimeException("signCsr failed (exit " + exitCode + "): " + csr.getSubject());
        return ViewCommand.loadCertificate(outPrefix + "_certificate.pem");
    }

    private static X509Certificate signHybridCsr(PKCS10CertificationRequest csr,
                                                  X509Certificate issuerCert,
                                                  java.security.PrivateKey issuerPrimaryKey,
                                                  java.security.PrivateKey issuerAltKey,
                                                  String profile, int pathLen) throws Exception {
        return signCsr(csr, issuerCert, issuerPrimaryKey, issuerAltKey, profile, pathLen);
    }

    private static int runVerifyChain(X509Certificate leaf, X509Certificate intermediate,
                                      X509Certificate trust) throws Exception {
        File leafFile  = writeCertFile(leaf);
        File chainFile = writeCertFile(intermediate);
        File trustFile = writeCertFile(trust);
        return new CommandLine(new VerifyCommand()).execute(
                "-in",    leafFile.getAbsolutePath(),
                "-chain", chainFile.getAbsolutePath(),
                "-trust", trustFile.getAbsolutePath());
    }

    /** Build a cert with expired validity (notAfter in the past). */
    private static X509Certificate buildExpiredCert(String subject, KeyPair kp,
                                                     X509Certificate issuerCert, KeyPair issuerKp,
                                                     boolean isCa) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 3 * 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() - 86400000L); // yesterday
        return buildRawCert(subject, kp, issuerCert, issuerKp, isCa, notBefore, notAfter,
                isCa ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                     : new KeyUsage(KeyUsage.digitalSignature), -1);
    }

    /** Build a cert with custom KeyUsage. */
    private static X509Certificate buildCertWithCustomKu(String subject, KeyPair kp,
                                                          X509Certificate issuerCert, KeyPair issuerKp,
                                                          boolean isCa, int kuBits) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        return buildRawCert(subject, kp, issuerCert, issuerKp, isCa, notBefore, notAfter,
                new KeyUsage(kuBits), -1);
    }

    /** Build a cert with given CA flag but no SKID/AKID (for negative tests). */
    private static X509Certificate buildCertWithIssuer(String subject, KeyPair kp,
                                                        X509Certificate issuerCert, KeyPair issuerKp,
                                                        boolean isCa) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        return buildRawCert(subject, kp, issuerCert, issuerKp, isCa, notBefore, notAfter,
                isCa ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                     : new KeyUsage(KeyUsage.digitalSignature), -1);
    }

    /** Build a self-signed CA cert with a specific pathLen. */
    private static X509Certificate buildSelfSignedCaWithPathLen(String subject, KeyPair kp,
                                                                  int pathLen) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name name = new X500Name(subject);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, new BigInteger(128, new java.security.SecureRandom()),
                notBefore, notAfter, name, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(kp.getPublic()));
        String sigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("RSA:3072").getAlgorithms()[0]);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    /** Build a cert with a custom BasicConstraints (for pathLen tests). */
    private static X509Certificate buildCertWithCustomBc(String subject, KeyPair kp,
                                                          X509Certificate issuerCert, KeyPair issuerKp,
                                                          BasicConstraints bc) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName("RFC1779"));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new java.security.SecureRandom()),
                notBefore, notAfter, new X500Name(subject), kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, bc);
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(kp.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(issuerCert.getEncoded())));
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuerCert);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    /** Build a cert with an AKID that points to a different key (foreign AKID). */
    private static X509Certificate buildCertWithForeignAkid(String subject, KeyPair kp,
                                                              X509Certificate issuerCert, KeyPair issuerKp,
                                                              KeyPair foreignKp) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName("RFC1779"));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new java.security.SecureRandom()),
                notBefore, notAfter, new X500Name(subject), kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(kp.getPublic()));
        // Use foreign key's SPKI to build an AKID that won't match the actual issuer SKID
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(foreignKp.getPublic().getEncoded())));
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuerCert);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    /** Build a hybrid cert directly (bypasses SignCommand validation). */
    private static X509Certificate buildHybridCertDirect(PKCS10CertificationRequest csr,
                                                          X509Certificate issuerCert,
                                                          KeyPair issuerPrimaryKp,
                                                          KeyPair issuerAltKp,
                                                          boolean isCa) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName("RFC1779"));
        java.security.PublicKey csrPubKey = new JcaPEMKeyConverter().setProvider("BC")
                .getPublicKey(csr.getSubjectPublicKeyInfo());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new java.security.SecureRandom()),
                notBefore, notAfter, csr.getSubject(), csrPubKey);
        builder.addExtension(Extension.basicConstraints, true,
                isCa ? new BasicConstraints(true) : new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                isCa ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                     : new KeyUsage(KeyUsage.digitalSignature));
        // Add alt public key from CSR
        org.bouncycastle.asn1.pkcs.Attribute[] altKeyAttrs =
                csr.getAttributes(Extension.subjectAltPublicKeyInfo);
        if (altKeyAttrs != null && altKeyAttrs.length > 0) {
            SubjectAltPublicKeyInfo eeAltKeyInfo = SubjectAltPublicKeyInfo.getInstance(
                    altKeyAttrs[0].getAttrValues().getObjectAt(0));
            builder.addExtension(Extension.subjectAltPublicKeyInfo, false, eeAltKeyInfo);
        }
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuerCert);
        ContentSigner primarySigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerPrimaryKp.getPrivate());
        String altSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("ML-DSA:65").getAlgorithms()[0]);
        ContentSigner altSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(altSigAlgo)
                .setProvider("BC").build(issuerAltKp.getPrivate());
        X509CertificateHolder holder = builder.build(primarySigner, false, altSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private static X509Certificate buildRawCert(String subject, KeyPair kp,
                                                  X509Certificate issuerCert, KeyPair issuerKp,
                                                  boolean isCa, Date notBefore, Date notAfter,
                                                  KeyUsage ku, int pathLen) throws Exception {
        X500Name issuerName = new X500Name(issuerCert.getSubjectX500Principal().getName("RFC1779"));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new java.security.SecureRandom()),
                notBefore, notAfter, new X500Name(subject), kp.getPublic());
        BasicConstraints bc = isCa
                ? (pathLen >= 0 ? new BasicConstraints(pathLen) : new BasicConstraints(true))
                : new BasicConstraints(false);
        builder.addExtension(Extension.basicConstraints, true, bc);
        builder.addExtension(Extension.keyUsage, true, ku);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(kp.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(issuerCert.getEncoded())));
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuerCert);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    static File writeCertFile(X509Certificate cert) throws Exception {
        File f = File.createTempFile("pqcli_cert", ".pem");
        f.deleteOnExit();
        CertificateGenerator.saveCertificateToFile(f.getAbsolutePath(), cert);
        return f;
    }

    static File writeKeyFile(java.security.PrivateKey key) throws Exception {
        File f = File.createTempFile("pqcli_key", ".pem");
        f.deleteOnExit();
        KeyGenerator.saveKeyToFile(f.getAbsolutePath(), key);
        return f;
    }

    static File writeCsrFile(PKCS10CertificationRequest csr) throws Exception {
        File f = File.createTempFile("pqcli_csr", ".pem");
        f.deleteOnExit();
        try (FileOutputStream os = new FileOutputStream(f)) {
            os.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
            os.write(KeyGenerator.wrapBase64(csr.getEncoded()).getBytes());
            os.write("-----END CERTIFICATE REQUEST-----\n".getBytes());
        }
        return f;
    }
}
