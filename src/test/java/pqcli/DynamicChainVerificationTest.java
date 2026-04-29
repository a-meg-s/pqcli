package pqcli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.junit.BeforeClass;
import org.junit.Test;
import picocli.CommandLine;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.*;

/**
 * Tests for the dynamic chain verifier (-untrusted / -trust).
 * Stage 2: path building + primary signatures.
 * Stage 3: policy checks (dates, BasicConstraints, KeyUsage, pathLen, SKID/AKID).
 */
public class DynamicChainVerificationTest {

    static {
        ProviderSetup.setupProvider();
    }

    // Classical RSA chain shared fixtures
    private static X509Certificate classicRoot;
    private static KeyPair          classicRootKp;
    private static X509Certificate classicInt;
    private static KeyPair          classicIntKp;
    private static X509Certificate classicInt2;
    private static KeyPair          classicInt2Kp;
    private static X509Certificate classicLeaf;

    // PQC and composite fixtures
    private static X509Certificate mlDsaRoot;
    private static KeyPair          mlDsaRootKp;
    private static X509Certificate mlDsaInt;
    private static KeyPair          mlDsaIntKp;
    private static X509Certificate mlDsaLeaf;

    private static X509Certificate compositeRoot;
    private static KeyPair          compositeRootKp;
    private static X509Certificate compositeLeaf;

    @BeforeClass
    public static void buildFixtures() throws Exception {
        // Classical root -> int -> int2 -> leaf (depth 3)
        classicRootKp = kp("RSA:3072");
        classicRoot   = selfSignedCa("CN=DC-Classic-Root", "RSA:3072", classicRootKp);
        classicIntKp  = kp("EC:secp256r1");
        classicInt    = issuedCa("CN=DC-Classic-Int", classicIntKp, classicRoot, classicRootKp);
        classicInt2Kp = kp("RSA:2048");
        classicInt2   = issuedCa("CN=DC-Classic-Int2", classicInt2Kp, classicInt, classicIntKp);
        KeyPair leafKp = kp("RSA:2048");
        classicLeaf   = issuedLeaf("CN=DC-Classic-Leaf", leafKp, classicInt2, classicInt2Kp);

        // ML-DSA root -> int -> leaf
        mlDsaRootKp = kp("ML-DSA:65");
        mlDsaRoot   = selfSignedCa("CN=DC-MLDSA-Root", "ML-DSA:65", mlDsaRootKp);
        mlDsaIntKp  = kp("ML-DSA:65");
        mlDsaInt    = issuedCa("CN=DC-MLDSA-Int", mlDsaIntKp, mlDsaRoot, mlDsaRootKp);
        KeyPair mlLeafKp = kp("ML-DSA:44");
        mlDsaLeaf   = issuedLeaf("CN=DC-MLDSA-Leaf", mlLeafKp, mlDsaInt, mlDsaIntKp);

        // Composite root -> leaf (direct, no intermediate)
        compositeRootKp = kp("RSA:3072_ML-DSA:65");
        compositeRoot   = selfSignedCa("CN=DC-Composite-Root", "RSA:3072_ML-DSA:65", compositeRootKp);
        KeyPair compLeafKp = kp("RSA:3072_ML-DSA:65");
        compositeLeaf   = issuedLeaf("CN=DC-Composite-Leaf", compLeafKp, compositeRoot, compositeRootKp);
    }

    // =========================================================================
    // Test 1: direct leaf -> trusted root (no intermediates)
    // =========================================================================

    @Test
    public void directLeafToRoot() throws Exception {
        // leaf directly signed by root; empty untrusted pool
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=DC-DirectRoot", "RSA:3072", rootKp);
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = issuedLeaf("CN=DC-DirectLeaf", leafKp, root, rootKp);

        File emptyUntrusted = emptyFile();
        assertEquals(0, runDynamic(leaf, emptyUntrusted, root));
    }

    // =========================================================================
    // Test 2: one intermediate via -untrusted
    // =========================================================================

    @Test
    public void oneIntermediateViaUntrusted() throws Exception {
        assertEquals(0, runDynamic(classicLeaf,
                PemBundleParserTest.writePemBundle(classicInt, classicInt2),
                classicRoot));
    }

    // =========================================================================
    // Test 3: depth-3 chain (root -> int -> int2 -> leaf)
    // =========================================================================

    @Test
    public void depthThreeChain() throws Exception {
        assertEquals(0, runDynamic(classicLeaf,
                PemBundleParserTest.writePemBundle(classicInt, classicInt2),
                classicRoot));
    }

    // =========================================================================
    // Test 4: multi-cert untrusted bundle; correct intermediate selected
    // =========================================================================

    @Test
    public void multiCertUntrustedBundleSelectsCorrectIntermediate() throws Exception {
        // Add a decoy intermediate (wrong key/wrong subject)
        KeyPair decoyKp = kp("RSA:3072");
        X509Certificate decoy = selfSignedCa("CN=DC-Decoy", "RSA:3072", decoyKp);
        // Bundle: decoy + correct intermediate
        File bundle = PemBundleParserTest.writePemBundle(decoy, classicInt, classicInt2);
        assertEquals(0, runDynamic(classicLeaf, bundle, classicRoot));
    }

    // =========================================================================
    // Test 5: multi-cert trust bundle; correct root selected
    // =========================================================================

    @Test
    public void multiCertTrustBundleSelectsCorrectRoot() throws Exception {
        // Trust bundle with an unrelated root and the real root
        KeyPair otherRootKp = kp("RSA:3072");
        X509Certificate otherRoot = selfSignedCa("CN=DC-OtherRoot", "RSA:3072", otherRootKp);
        File trustBundle = PemBundleParserTest.writePemBundle(otherRoot, classicRoot);
        File untrustedBundle = PemBundleParserTest.writePemBundle(classicInt, classicInt2);
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",        writeCert(classicLeaf).getAbsolutePath(),
                "-untrusted", untrustedBundle.getAbsolutePath(),
                "-trust",     trustBundle.getAbsolutePath());
        assertEquals(0, exitCode);
    }

    // =========================================================================
    // Test 6: missing intermediate -> no path found
    // =========================================================================

    @Test
    public void missingIntermediateFailsWithNoPath() throws Exception {
        // Leaf is signed by classicInt2, but we only provide classicInt (classicInt2 is missing)
        File bundle = PemBundleParserTest.writePemBundle(classicInt);
        assertEquals(1, runDynamic(classicLeaf, bundle, classicRoot));
    }

    // =========================================================================
    // Test 7: wrong intermediate (signed by a different key) fails
    // =========================================================================

    @Test
    public void wrongIntermediateFailsSignatureCheck() throws Exception {
        // Build a leaf signed directly by classicRoot, but claim classicInt2 is its issuer.
        // classicLeaf is signed by classicInt2; if we put a wrong intermediate (different key)
        // in the bundle, the DFS won't find a valid path.
        KeyPair wrongKp = kp("RSA:2048");
        X509Certificate wrongInt = selfSignedCa("CN=DC-Classic-Int2", "RSA:2048", wrongKp);
        // Bundle: classicInt (correct) + wrongInt (same subject DN as classicInt2 but wrong key)
        File bundle = PemBundleParserTest.writePemBundle(classicInt, wrongInt);
        assertEquals(1, runDynamic(classicLeaf, bundle, classicRoot));
    }

    // =========================================================================
    // Test 8: expired intermediate fails
    // =========================================================================

    @Test
    public void expiredIntermediateFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=Pol-Root", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:2048");
        X509Certificate expiredInt = buildRawIssuedCert("CN=Pol-ExpInt", intKp,
                root, rootKp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 3 * 86400000L),
                new Date(System.currentTimeMillis() - 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=Pol-ExpLeaf", leafKp,
                expiredInt, intKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(expiredInt), root));
    }

    // =========================================================================
    // Test 9: CA=false intermediate fails
    // =========================================================================

    @Test
    public void caFalseIntermediateFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=Pol-Root2", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:2048");
        // Build an issued cert with CA=false (bypasses SignCommand)
        X509Certificate falseCaInt = buildRawIssuedCert("CN=Pol-FalseCaInt", intKp,
                root, rootKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=Pol-FalseCaLeaf", leafKp,
                falseCaInt, intKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(falseCaInt), root));
    }

    // =========================================================================
    // Test 10: missing keyCertSign on intermediate fails
    // =========================================================================

    @Test
    public void missingKeyCertSignFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=Pol-Root3", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:2048");
        // CA=true but KeyUsage only digitalSignature (no keyCertSign)
        X509Certificate badKuInt = buildRawIssuedCert("CN=Pol-BadKuInt", intKp,
                root, rootKp, true, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=Pol-BadKuLeaf", leafKp,
                badKuInt, intKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(badKuInt), root));
    }

    // =========================================================================
    // Test 11: pathLen=0 on root with one intermediate fails
    //   path: [leaf(0), int(1), root(2)], root at i=2: subordinateCaCount = 1 > 0
    // =========================================================================

    @Test
    public void rootPathLenZeroWithOneIntermediateFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = buildSelfSignedCaWithPathLen("CN=PL-Root-PL0", rootKp, 0);
        KeyPair intKp = kp("RSA:2048");
        X509Certificate inter = buildRawIssuedCert("CN=PL-Int", intKp,
                root, rootKp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=PL-Leaf", leafKp,
                inter, intKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(inter), root));
    }

    // =========================================================================
    // Test 12: pathLen=1 on root with one intermediate passes
    //   path: [leaf(0), int(1), root(2)], root at i=2: subordinateCaCount = 1 <= 1
    // =========================================================================

    @Test
    public void rootPathLenOneWithOneIntermediatePasses() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = buildSelfSignedCaWithPathLen("CN=PL-Root-PL1", rootKp, 1);
        KeyPair intKp = kp("RSA:2048");
        X509Certificate inter = buildRawIssuedCert("CN=PL-Int1", intKp,
                root, rootKp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=PL-Leaf1", leafKp,
                inter, intKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(0, runDynamic(leaf, PemBundleParserTest.writePemBundle(inter), root));
    }

    // =========================================================================
    // Test 13: pathLen=1 on root with two intermediates fails
    //   path: [leaf(0), int2(1), int1(2), root(3)], root at i=3: subordinateCaCount = 2 > 1
    // =========================================================================

    @Test
    public void rootPathLenOneWithTwoIntermediatesFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = buildSelfSignedCaWithPathLen("CN=PL-Root-2Int-PL1", rootKp, 1);
        KeyPair int1Kp = kp("RSA:2048");
        X509Certificate int1 = buildRawIssuedCert("CN=PL-Int1-2Int", int1Kp,
                root, rootKp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair int2Kp = kp("RSA:2048");
        X509Certificate int2 = buildRawIssuedCert("CN=PL-Int2-2Int", int2Kp,
                int1, int1Kp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=PL-Leaf-2Int", leafKp,
                int2, int2Kp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(int1, int2), root));
    }

    // =========================================================================
    // Test 13b: pathLen=2 on root with two intermediates passes
    //   path: [leaf(0), int2(1), int1(2), root(3)], root at i=3: subordinateCaCount = 2 <= 2
    // =========================================================================

    @Test
    public void rootPathLenTwoWithTwoIntermediatesPasses() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = buildSelfSignedCaWithPathLen("CN=PL-Root-2Int-PL2", rootKp, 2);
        KeyPair int1Kp = kp("RSA:2048");
        X509Certificate int1 = buildRawIssuedCert("CN=PL-Int1-PL2", int1Kp,
                root, rootKp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair int2Kp = kp("RSA:2048");
        X509Certificate int2 = buildRawIssuedCert("CN=PL-Int2-PL2", int2Kp,
                int1, int1Kp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=PL-Leaf-PL2", leafKp,
                int2, int2Kp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(0, runDynamic(leaf, PemBundleParserTest.writePemBundle(int1, int2), root));
    }

    // =========================================================================
    // Test 13c: upper intermediate pathLen=0 with lower intermediate below fails
    //   path: [leaf(0), int2(1), int1(2), root(3)], int1 at i=2: subordinateCaCount = 1 > 0
    // =========================================================================

    @Test
    public void upperIntermediatePathLenZeroWithLowerIntermediateFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=PL-Root-13c", "RSA:3072", rootKp);
        KeyPair int1Kp = kp("RSA:2048");
        // int1 has pathLen=0 — no intermediates may follow it
        X509Certificate int1 = buildRawIssuedCertWithPathLen("CN=PL-Int1-13c", int1Kp,
                root, rootKp, 0);
        KeyPair int2Kp = kp("RSA:2048");
        // int2 is below int1, making int1's pathLen=0 violated
        X509Certificate int2 = buildRawIssuedCert("CN=PL-Int2-13c", int2Kp,
                int1, int1Kp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=PL-Leaf-13c", leafKp,
                int2, int2Kp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(int1, int2), root));
    }

    // =========================================================================
    // Test 13d: lower intermediate pathLen=0 with only leaf below passes
    //   path: [leaf(0), int2(1), int1(2), root(3)], int2 at i=1: subordinateCaCount = 0 <= 0
    // =========================================================================

    @Test
    public void lowerIntermediatePathLenZeroWithOnlyLeafBelowPasses() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=PL-Root-13d", "RSA:3072", rootKp);
        KeyPair int1Kp = kp("RSA:2048");
        X509Certificate int1 = buildRawIssuedCert("CN=PL-Int1-13d", int1Kp,
                root, rootKp, true, KeyUsage.keyCertSign | KeyUsage.cRLSign,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        KeyPair int2Kp = kp("RSA:2048");
        // int2 has pathLen=0 — only a leaf may follow it
        X509Certificate int2 = buildRawIssuedCertWithPathLen("CN=PL-Int2-13d", int2Kp,
                int1, int1Kp, 0);
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=PL-Leaf-13d", leafKp,
                int2, int2Kp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(0, runDynamic(leaf, PemBundleParserTest.writePemBundle(int1, int2), root));
    }

    // =========================================================================
    // Test 14: SKID/AKID mismatch fails
    // =========================================================================

    @Test
    public void skidAkidMismatchFails() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=Pol-AKID-Root", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:2048");
        // Build intermediate with an AKID that points to a foreign key (not root's SKID)
        KeyPair foreignKp = kp("RSA:2048");
        X509Certificate intWithForeignAkid = buildIssuedCertWithForeignAkid(
                "CN=Pol-AKID-Int", intKp, root, rootKp, foreignKp);
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = buildRawIssuedCert("CN=Pol-AKID-Leaf", leafKp,
                intWithForeignAkid, intKp, false, KeyUsage.digitalSignature,
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L));
        assertEquals(1, runDynamic(leaf, PemBundleParserTest.writePemBundle(intWithForeignAkid), root));
    }

    // =========================================================================
    // Test 15: composite dynamic chain (primary sig only)
    // =========================================================================

    @Test
    public void compositeDynamicChain() throws Exception {
        assertEquals(0, runDynamic(compositeLeaf, emptyFile(), compositeRoot));
    }

    // =========================================================================
    // Test 16: PQC (ML-DSA) dynamic chain (primary sig only)
    // =========================================================================

    @Test
    public void pqcMlDsaDynamicChain() throws Exception {
        assertEquals(0, runDynamic(mlDsaLeaf,
                PemBundleParserTest.writePemBundle(mlDsaInt),
                mlDsaRoot));
    }

    // =========================================================================
    // Test 17: hybrid dynamic chain with alt-sig checks passes
    // =========================================================================

    @Test
    public void hybridDynamicChainWithAltSigPasses() throws Exception {
        // Build RSA+ML-DSA hybrid chain using ChainVerificationTest fixtures as a model
        KeyPair rootPrimary = kp("RSA:3072");
        KeyPair rootAlt     = kp("ML-DSA:65");
        X509Certificate hybridRoot = CertificateGenerator.generateCertificate(
                new AlgorithmSet("RSA:3072,ML-DSA:65"), rootPrimary, rootAlt, "CN=Dyn-Hybrid-Root", 1.0);

        KeyPair intPrimary = kp("RSA:3072");
        KeyPair intAlt     = kp("ML-DSA:65");
        org.bouncycastle.pkcs.PKCS10CertificationRequest hybridIntCsr =
                buildHybridCsr("CN=Dyn-Hybrid-Int", intPrimary, intAlt);
        X509Certificate hybridInt = buildHybridIssuedCert(hybridIntCsr,
                hybridRoot, rootPrimary, rootAlt, true);

        KeyPair leafPrimary = kp("RSA:3072");
        KeyPair leafAlt     = kp("ML-DSA:65");
        org.bouncycastle.pkcs.PKCS10CertificationRequest hybridLeafCsr =
                buildHybridCsr("CN=Dyn-Hybrid-Leaf", leafPrimary, leafAlt);
        X509Certificate hybridLeaf = buildHybridIssuedCert(hybridLeafCsr,
                hybridInt, intPrimary, intAlt, false);

        assertEquals(0, runDynamic(hybridLeaf,
                PemBundleParserTest.writePemBundle(hybridInt), hybridRoot));
    }

    // =========================================================================
    // Test 18: malformed hybrid extensions in dynamic chain fails
    // =========================================================================

    @Test
    public void malformedHybridExtensionInDynamicChainFails() throws Exception {
        KeyPair rootPrimary = kp("RSA:3072");
        KeyPair rootAlt     = kp("ML-DSA:65");
        X509Certificate hybridRoot = CertificateGenerator.generateCertificate(
                new AlgorithmSet("RSA:3072,ML-DSA:65"), rootPrimary, rootAlt, "CN=Dyn-Hybrid-Root2", 1.0);

        // Build a leaf with ONLY SubjectAltPublicKeyInfo (missing AltSigAlgo + AltSigValue)
        KeyPair leafKp = kp("RSA:3072");
        KeyPair altKp  = kp("ML-DSA:65");
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo altSpki =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(altKp.getPublic().getEncoded());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(hybridRoot.getSubjectX500Principal().getName("RFC1779")),
                new BigInteger(128, new SecureRandom()),
                new Date(System.currentTimeMillis() - 86400000L),
                new Date(System.currentTimeMillis() + 86400000L),
                new X500Name("CN=Dyn-Malformed-Leaf"), leafKp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.subjectAltPublicKeyInfo, false,
                new org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo(altSpki));
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                SignCommand.deriveSigAlgoFromCaKey(hybridRoot))
                .setProvider("BC").build(rootPrimary.getPrivate());
        X509Certificate malformedLeaf = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(b.build(signer));

        assertEquals(1, runDynamic(malformedLeaf, emptyFile(), hybridRoot));
    }

    // =========================================================================
    // Test 19: backward compat — old -chain -trust still works via verifyChain()
    // =========================================================================

    @Test
    public void backwardCompatChainTrustStillWorks() throws Exception {
        // Using -chain/-trust must still go through the existing verifyChain() path
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",    writeCert(classicLeaf).getAbsolutePath(),
                "-chain", writeCert(classicInt2).getAbsolutePath(),
                "-trust", writeCert(classicInt).getAbsolutePath()); // wrong trust => expect fail
        // We just need to verify the old mode is dispatched without errors about unknown flags
        // A more meaningful test: build a 3-tier chain that verifyChain can handle
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=BC-Root", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:3072");
        X509Certificate inter = issuedCa("CN=BC-Int", intKp, root, rootKp);
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = issuedLeaf("CN=BC-Leaf", leafKp, inter, intKp);
        int code = new CommandLine(new VerifyCommand()).execute(
                "-in",    writeCert(leaf).getAbsolutePath(),
                "-chain", writeCert(inter).getAbsolutePath(),
                "-trust", writeCert(root).getAbsolutePath());
        assertEquals("Old -chain/-trust mode must still return 0 for valid chain", 0, code);
    }

    // =========================================================================
    // Test 20: --related-cert remains mutually exclusive with -untrusted/-trust
    // =========================================================================

    @Test
    public void relatedCertMutuallyExclusiveWithUntrusted() throws Exception {
        File dummy = emptyFile();
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",           writeCert(classicLeaf).getAbsolutePath(),
                "-untrusted",    dummy.getAbsolutePath(),
                "-trust",        dummy.getAbsolutePath(),
                "--related-cert", dummy.getAbsolutePath());
        assertEquals("--related-cert must be rejected when combined with -untrusted/-trust", 1, exitCode);
    }

    // =========================================================================
    // Test 21: --show-chain prints indexed path
    // =========================================================================

    @Test
    public void showChainPrintsIndexedPath() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=SC-Root", "RSA:3072", rootKp);
        KeyPair intKp = kp("RSA:2048");
        X509Certificate inter = issuedCa("CN=SC-Int", intKp, root, rootKp);
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = issuedLeaf("CN=SC-Leaf", leafKp, inter, intKp);

        File outFile = File.createTempFile("show_chain_out", ".txt");
        outFile.deleteOnExit();

        java.io.ByteArrayOutputStream captured = new java.io.ByteArrayOutputStream();
        java.io.PrintStream origOut = System.out;
        System.setOut(new java.io.PrintStream(captured));
        int exitCode;
        try {
            exitCode = new CommandLine(new VerifyCommand()).execute(
                    "-in",        writeCert(leaf).getAbsolutePath(),
                    "-untrusted", PemBundleParserTest.writePemBundle(inter).getAbsolutePath(),
                    "-trust",     writeCert(root).getAbsolutePath(),
                    "--show-chain");
        } finally {
            System.setOut(origOut);
        }
        assertEquals(0, exitCode);
        String out = captured.toString();
        assertTrue("--show-chain output must contain [0]", out.contains("[0]"));
        assertTrue("--show-chain output must contain [1]", out.contains("[1]"));
        assertTrue("--show-chain output must contain [2]", out.contains("[2]"));
    }

    // =========================================================================
    // Test: -trust alone (direct leaf→root, no -untrusted provided)
    // =========================================================================

    @Test
    public void trustAloneDirectLeafToRoot() throws Exception {
        KeyPair rootKp = kp("RSA:3072");
        X509Certificate root = selfSignedCa("CN=TA-Root", "RSA:3072", rootKp);
        KeyPair leafKp = kp("RSA:2048");
        X509Certificate leaf = issuedLeaf("CN=TA-Leaf", leafKp, root, rootKp);
        // No -untrusted argument — -trust alone triggers dynamic verifier with empty pool
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",    writeCert(leaf).getAbsolutePath(),
                "-trust", writeCert(root).getAbsolutePath());
        assertEquals(0, exitCode);
    }

    // =========================================================================
    // Test 25: DER equality — non-trusted lookalike must not be accepted as trust anchor
    // =========================================================================

    @Test
    public void lookalikeRootNotAcceptedAsTrustAnchor() throws Exception {
        // Build a fresh root with same subject DN as classicRoot but a different key
        KeyPair lookalikeKp = kp("RSA:3072");
        X509Certificate lookalike = selfSignedCa(
                classicRoot.getSubjectX500Principal().getName(), "RSA:3072", lookalikeKp);
        assertFalse("Lookalike must not be DER-equal to classicRoot",
                Arrays.equals(lookalike.getEncoded(), classicRoot.getEncoded()));

        // Trust bundle contains the lookalike, NOT the real root
        File trustBundle = PemBundleParserTest.writePemBundle(lookalike);
        File untrustedBundle = PemBundleParserTest.writePemBundle(classicInt, classicInt2);
        int exitCode = new CommandLine(new VerifyCommand()).execute(
                "-in",        writeCert(classicLeaf).getAbsolutePath(),
                "-untrusted", untrustedBundle.getAbsolutePath(),
                "-trust",     trustBundle.getAbsolutePath());
        assertEquals("Lookalike root must not complete the path", 1, exitCode);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static KeyPair kp(String algo) throws Exception {
        return KeyGenerator.generateKeyPair(new AlgorithmSet(algo).getAlgorithms());
    }

    private static X509Certificate selfSignedCa(String subject, String algo, KeyPair kp) throws Exception {
        return CertificateGenerator.generateCertificate(new AlgorithmSet(algo), kp, null, subject, 1.0);
    }

    private static X509Certificate issuedCa(String subject, KeyPair kp,
                                             X509Certificate issuer, KeyPair issuerKp) throws Exception {
        return runSign(subject, kp, issuer, issuerKp, "intermediate-ca", -1);
    }

    private static X509Certificate issuedLeaf(String subject, KeyPair kp,
                                               X509Certificate issuer, KeyPair issuerKp) throws Exception {
        return runSign(subject, kp, issuer, issuerKp, "leaf", -1);
    }

    private static X509Certificate runSign(String subject, KeyPair kp,
                                            X509Certificate issuer, KeyPair issuerKp,
                                            String profile, int pathLen) throws Exception {
        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = buildCsr(subject, kp);
        File issuerCert = writeCert(issuer);
        File issuerKey  = ChainVerificationTest.writeKeyFile(issuerKp.getPrivate());
        File csrFile    = ChainVerificationTest.writeCsrFile(csr);
        File outDir     = java.nio.file.Files.createTempDirectory("dc_sign").toFile();
        String outPrefix = new File(outDir, "out").getAbsolutePath();
        java.util.List<String> args = new java.util.ArrayList<>(java.util.Arrays.asList(
                "-csr", csrFile.getAbsolutePath(),
                "-CAcert", issuerCert.getAbsolutePath(),
                "-CAkey",  issuerKey.getAbsolutePath(),
                "--profile", profile,
                "-out", outPrefix));
        if (pathLen >= 0) { args.add("--path-len"); args.add(String.valueOf(pathLen)); }
        int code = new CommandLine(new SignCommand()).execute(args.toArray(new String[0]));
        if (code != 0) throw new RuntimeException("sign failed for " + subject);
        return ViewCommand.loadCertificate(outPrefix + "_certificate.pem");
    }

    private static org.bouncycastle.pkcs.PKCS10CertificationRequest buildCsr(
            String subject, KeyPair kp) throws Exception {
        java.security.PublicKey pub = kp.getPublic();
        String algo;
        if (pub instanceof java.security.interfaces.RSAPublicKey)      algo = "SHA256withRSA";
        else if (pub instanceof java.security.interfaces.ECPublicKey)   algo = "SHA256withECDSA";
        else                                                             algo = pub.getAlgorithm();
        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(algo)
                        .setProvider("BC").build(kp.getPrivate());
        return new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                new org.bouncycastle.asn1.x500.X500Name(subject), pub).build(signer);
    }

    static int runDynamic(X509Certificate leaf, File untrustedBundle, X509Certificate... trustCerts)
            throws Exception {
        File trustBundle = PemBundleParserTest.writePemBundle(trustCerts);
        return new CommandLine(new VerifyCommand()).execute(
                "-in",        writeCert(leaf).getAbsolutePath(),
                "-untrusted", untrustedBundle.getAbsolutePath(),
                "-trust",     trustBundle.getAbsolutePath());
    }

    static File writeCert(X509Certificate cert) throws Exception {
        return ChainVerificationTest.writeCertFile(cert);
    }

    static File emptyFile() throws Exception {
        File f = File.createTempFile("empty_untrusted", ".pem");
        f.deleteOnExit();
        return f;
    }

    // -------------------------------------------------------------------------
    // Raw cert builders (bypass SignCommand validation for negative test cases)
    // -------------------------------------------------------------------------

    private static X509Certificate buildRawIssuedCert(
            String subject, KeyPair kp, X509Certificate issuer, KeyPair issuerKp,
            boolean isCa, int kuBits, Date notBefore, Date notAfter) throws Exception {
        X500Name issuerName = new X500Name(issuer.getSubjectX500Principal().getName("RFC1779"));
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new SecureRandom()),
                notBefore, notAfter, new X500Name(subject), kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(kuBits));
        JcaX509ExtensionUtils eu = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, eu.createSubjectKeyIdentifier(kp.getPublic()));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                eu.createAuthorityKeyIdentifier(new X509CertificateHolder(issuer.getEncoded())));
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuer);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    private static X509Certificate buildRawIssuedCertWithPathLen(
            String subject, KeyPair kp, X509Certificate issuer, KeyPair issuerKp,
            int pathLen) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name issuerName = new X500Name(issuer.getSubjectX500Principal().getName("RFC1779"));
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new SecureRandom()),
                notBefore, notAfter, new X500Name(subject), kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils eu = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, eu.createSubjectKeyIdentifier(kp.getPublic()));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                eu.createAuthorityKeyIdentifier(new X509CertificateHolder(issuer.getEncoded())));
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuer);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    private static X509Certificate buildSelfSignedCaWithPathLen(
            String subject, KeyPair kp, int pathLen) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name name = new X500Name(subject);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                name, new BigInteger(128, new SecureRandom()),
                notBefore, notAfter, name, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils eu = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, eu.createSubjectKeyIdentifier(kp.getPublic()));
        b.addExtension(Extension.authorityKeyIdentifier, false,
                eu.createAuthorityKeyIdentifier(kp.getPublic()));
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                sigAlgoFromKeyPair(kp)).setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    private static X509Certificate buildIssuedCertWithForeignAkid(
            String subject, KeyPair kp, X509Certificate issuer, KeyPair issuerKp,
            KeyPair foreignKp) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name issuerName = new X500Name(issuer.getSubjectX500Principal().getName("RFC1779"));
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new SecureRandom()),
                notBefore, notAfter, new X500Name(subject), kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils eu = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, eu.createSubjectKeyIdentifier(kp.getPublic()));
        // AKID from foreign key — intentionally does NOT match issuer's SKID
        b.addExtension(Extension.authorityKeyIdentifier, false,
                eu.createAuthorityKeyIdentifier(
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                                foreignKp.getPublic().getEncoded())));
        String sigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuer);
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(sigAlgo)
                .setProvider("BC").build(issuerKp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    private static String sigAlgoFromKeyPair(KeyPair kp) {
        java.security.PublicKey pub = kp.getPublic();
        if (pub instanceof java.security.interfaces.RSAPublicKey) {
            int bits = ((java.security.interfaces.RSAPublicKey) pub).getModulus().bitLength();
            return bits >= 4096 ? "SHA512withRSA" : bits >= 3072 ? "SHA384withRSA" : "SHA256withRSA";
        } else if (pub instanceof java.security.interfaces.ECPublicKey) {
            return "SHA256withECDSA";
        }
        return pub.getAlgorithm();
    }

    private static org.bouncycastle.pkcs.PKCS10CertificationRequest buildHybridCsr(
            String subject, KeyPair primary, KeyPair alt) throws Exception {
        String primarySigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("RSA:3072,ML-DSA:65").getAlgorithms()[0]);
        String altSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("RSA:3072,ML-DSA:65").getAltAlgorithms()[0]);
        ContentSigner primarySigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(primarySigAlgo)
                .setProvider("BC").build(primary.getPrivate());
        ContentSigner altSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(altSigAlgo)
                .setProvider("BC").build(alt.getPrivate());
        return new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                new X500Name(subject), primary.getPublic())
                .build(primarySigner, alt.getPublic(), altSigner);
    }

    private static X509Certificate buildHybridIssuedCert(
            org.bouncycastle.pkcs.PKCS10CertificationRequest csr,
            X509Certificate issuer, KeyPair issuerPrimary, KeyPair issuerAlt,
            boolean isCa) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 86400000L);
        X500Name issuerName = new X500Name(issuer.getSubjectX500Principal().getName("RFC1779"));
        java.security.PublicKey csrPubKey = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                .setProvider("BC").getPublicKey(csr.getSubjectPublicKeyInfo());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, new BigInteger(128, new SecureRandom()),
                notBefore, notAfter, csr.getSubject(), csrPubKey);
        b.addExtension(Extension.basicConstraints, true,
                isCa ? new BasicConstraints(true) : new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true,
                isCa ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                     : new KeyUsage(KeyUsage.digitalSignature));
        org.bouncycastle.asn1.pkcs.Attribute[] altKeyAttrs = csr.getAttributes(Extension.subjectAltPublicKeyInfo);
        if (altKeyAttrs != null && altKeyAttrs.length > 0) {
            org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo eeAltKeyInfo =
                    org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo.getInstance(
                            altKeyAttrs[0].getAttrValues().getObjectAt(0));
            b.addExtension(Extension.subjectAltPublicKeyInfo, false, eeAltKeyInfo);
        }
        String primarySigAlgo = SignCommand.deriveSigAlgoFromCaKey(issuer);
        ContentSigner primarySigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(primarySigAlgo)
                .setProvider("BC").build(issuerPrimary.getPrivate());
        String altSigAlgo = CertificateGenerator.getSuitableSignatureAlgorithm(
                new AlgorithmSet("ML-DSA:65").getAlgorithms()[0]);
        ContentSigner altSigner = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(altSigAlgo)
                .setProvider("BC").build(issuerAlt.getPrivate());
        org.bouncycastle.cert.X509CertificateHolder holder = b.build(primarySigner, false, altSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }
}
