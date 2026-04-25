package pqcli;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.asn1.x509.AltSignatureAlgorithm;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.Callable;

@Command(name = "sign", description = "Sign a CSR with a CA key to produce a chain-of-trust certificate")
public class SignCommand implements Callable<Integer> {

    @Option(names = {"-csr"}, required = true, description = "PKCS#10 CSR file (PEM)")
    private String csrFile;

    @Option(names = {"-CAcert"}, required = true, description = "CA certificate file (PEM)")
    private String caCertFile;

    @Option(names = {"-CAkey"}, required = true, description = "CA private key file (PEM, PKCS#8 or PKCS#1)")
    private String caKeyFile;

    @Option(names = {"-CAaltkey"}, description = "CA alternative private key file (PEM). Required when signing a hybrid CSR.")
    private String caAltKeyFile;

    @Option(names = {"-days", "-d"}, defaultValue = "365",
            description = "Certificate validity in days (default: 365)")
    private int days;

    @Option(names = {"-out", "-o"}, defaultValue = "",
            description = "Output filename prefix (e.g. 'signed' → signed_certificate.pem)")
    private String outPrefix;

    @Option(names = "--timing", defaultValue = "false",
            description = "Print signing timing")
    private boolean printTiming;

    @Option(names = "--profile", defaultValue = "leaf",
            description = "Certificate profile: leaf (default) or intermediate-ca")
    private String profileStr;

    @Option(names = "--path-len", defaultValue = "-1",
            description = "Path length constraint for intermediate-ca profile (>= 0). Not valid for leaf.")
    private int pathLen;

    private String prefixed(String name) {
        return outPrefix.isEmpty() ? name : outPrefix + "_" + name;
    }

    @Override
    public Integer call() throws Exception {
        ProviderSetup.setupProvider();
        try {
            // Parse and validate profile
            CertificateProfile profile;
            try {
                profile = CertificateProfile.valueOf(profileStr.toUpperCase().replace('-', '_'));
            } catch (IllegalArgumentException e) {
                System.err.println("Error: Unknown profile '" + profileStr + "'. Valid values: leaf, intermediate-ca");
                return 1;
            }
            if (pathLen >= 0 && profile != CertificateProfile.INTERMEDIATE_CA) {
                System.err.println("Error: --path-len is only valid with --profile intermediate-ca");
                return 1;
            }

            // Step 1: Load inputs
            X509Certificate caCert = ViewCommand.loadCertificate(caCertFile);
            PrivateKey caPrivateKey = loadPrivKey(caKeyFile);
            PKCS10CertificationRequest csr = loadCsr(csrFile);

            // Step 2: Primary CSR PoP — enforced for ALL signing paths (hybrid and non-hybrid).
            // SignCommand previously never verified the CSR signature; this closes that gap.
            SubjectPublicKeyInfo csrSpki = csr.getSubjectPublicKeyInfo();
            PublicKey csrPubKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(csrSpki);
            ContentVerifierProvider primaryCsrVerifier = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(csrPubKey);
            if (!csr.isSignatureValid(primaryCsrVerifier)) {
                System.err.println("Error: CSR primary signature is invalid (proof of possession failed).");
                return 1;
            }

            // Validate issuer is a CA cert capable of signing
            if (caCert.getBasicConstraints() < 0) {
                System.err.println("Error: Issuer certificate is not a CA certificate (BasicConstraints CA=true required).");
                return 1;
            }
            boolean[] caKu = caCert.getKeyUsage();
            if (caKu != null && !caKu[5]) {
                System.err.println("Error: Issuer certificate KeyUsage does not allow certificate signing (keyCertSign required).");
                return 1;
            }

            // Common certificate structure — used by both hybrid and non-hybrid paths
            String sigAlgo = deriveSigAlgoFromCaKey(caCert);
            long t0 = System.currentTimeMillis();
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + (long) days * 86400000L);
            X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName("RFC1779"));
            X500Name subject = csr.getSubject();

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, CertificateGenerator.generateSerial(),
                    notBefore, notAfter, subject,
                    csrPubKey);
            // Profile-conditional extensions — applied to both hybrid and non-hybrid paths.
            if (profile == CertificateProfile.INTERMEDIATE_CA) {
                BasicConstraints bc = (pathLen >= 0) ? new BasicConstraints(pathLen) : new BasicConstraints(true);
                certBuilder.addExtension(Extension.basicConstraints, true, bc);
                certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            } else {
                certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            }
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    extUtils.createSubjectKeyIdentifier(csrPubKey));
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(caCert.getEncoded())));
            ContentSigner primarySigner = new JcaContentSignerBuilder(sigAlgo)
                    .setProvider("BC").build(caPrivateKey);

            X509Certificate certificate;
            String altSigAlgoForOutput = null;
            boolean isHybridIssued = false;

            // Step 3: Detect hybrid
            if (csr.hasAltPublicKey()) {
                // === HYBRID PATH ===

                // Step 4: Pre-issuance guards — require -CAaltkey and a hybrid-capable CA cert
                if (caAltKeyFile == null) {
                    System.err.println("Error: CSR contains hybrid alt content but -CAaltkey was not provided.");
                    return 1;
                }
                X509CertificateHolder caHolder = new X509CertificateHolder(caCert.getEncoded());
                Extensions caExts = caHolder.getExtensions();
                boolean caHasAltKey  = caExts != null
                        && caExts.getExtension(Extension.subjectAltPublicKeyInfo) != null;
                boolean caHasAltAlgo = caExts != null
                        && caExts.getExtension(Extension.altSignatureAlgorithm) != null;
                if (!caHasAltKey || !caHasAltAlgo) {
                    System.err.println("Error: CSR is hybrid but CA cert is not a hybrid cert " +
                        "(required extensions SubjectAltPublicKeyInfo and/or AltSignatureAlgorithm are missing).");
                    return 1;
                }

                // Step 5: Load CA alt private key
                PrivateKey caAltPrivateKey = loadPrivKey(caAltKeyFile);

                // Step 6: Extract CA cert alt public key + alt sig algorithm.
                // Issuance policy: the alt signing algorithm is inherited from the CA cert's own alt
                // signature. This is a deliberate choice — the issued EE cert uses the same alt algorithm
                // as the CA cert. The -CAaltkey private key must correspond to the CA cert's alt public key.
                AltSignatureAlgorithm altSigAlgoExt = AltSignatureAlgorithm.fromExtensions(caExts);
                // caHasAltAlgo confirmed in Step 4, so altSigAlgoExt != null here
                String altSigAlgoOid = altSigAlgoExt.getAlgorithm().getAlgorithm().getId();
                String altSigAlgo = ViewCommand.oidToName(altSigAlgoOid); // e.g. "ML-DSA-65"

                SubjectAltPublicKeyInfo caAltKeyInfo = SubjectAltPublicKeyInfo.fromExtensions(caExts);
                SubjectPublicKeyInfo caAltSpki = SubjectPublicKeyInfo.getInstance(
                        caAltKeyInfo.toASN1Primitive());
                PublicKey caAltPubKey = new JcaPEMKeyConverter().setProvider("BC")
                        .getPublicKey(caAltSpki);

                // Step 7: Validate CA alt key ↔ CA cert alt public key.
                // BC-native sign-then-verify using JcaContentSignerBuilder / ContentVerifierProvider.
                // JCA Signature API (java.security.Signature) is not used anywhere in this codebase.
                try {
                    ContentSigner testSigner = new JcaContentSignerBuilder(altSigAlgo)
                            .setProvider("BC").build(caAltPrivateKey);
                    testSigner.getOutputStream().write(
                            "pqcli-ca-alt-key-check".getBytes(StandardCharsets.UTF_8));
                    byte[] testSig = testSigner.getSignature();
                    ContentVerifierProvider testCVP = new JcaContentVerifierProviderBuilder()
                            .setProvider("BC").build(caAltPubKey);
                    ContentVerifier cv = testCVP.get(testSigner.getAlgorithmIdentifier());
                    cv.getOutputStream().write(
                            "pqcli-ca-alt-key-check".getBytes(StandardCharsets.UTF_8));
                    if (!cv.verify(testSig)) {
                        System.err.println("Error: -CAaltkey does not correspond to the CA cert's alt public key.");
                        return 1;
                    }
                } catch (Exception e) {
                    System.err.println("Error: -CAaltkey does not correspond to the CA cert's alt public key: "
                            + e.getMessage());
                    return 1;
                }

                // Step 8: Extract EE alt public key from CSR.
                // BC stores the alt public key as a SubjectAltPublicKeyInfo attribute at OID 2.5.29.72
                // (confirmed from BC Javadoc; NOT inside extensionRequest). The .toASN1Primitive()
                // conversion is the same as VerifyCommand.java:70-72 already uses in production.
                Attribute[] altKeyAttrs = csr.getAttributes(Extension.subjectAltPublicKeyInfo);
                if (altKeyAttrs == null || altKeyAttrs.length == 0) {
                    System.err.println("Error: Could not extract alt public key from hybrid CSR " +
                        "(attribute at OID 2.5.29.72 is missing).");
                    return 1;
                }
                SubjectAltPublicKeyInfo eeAltKeyInfo = SubjectAltPublicKeyInfo.getInstance(
                        altKeyAttrs[0].getAttrValues().getObjectAt(0));
                SubjectPublicKeyInfo eeAltSpki = SubjectPublicKeyInfo.getInstance(
                        eeAltKeyInfo.toASN1Primitive());
                PublicKey eeAltPubKey = new JcaPEMKeyConverter().setProvider("BC")
                        .getPublicKey(eeAltSpki);

                // Step 9: EE alt PoP
                ContentVerifierProvider eeAltVerifier = new JcaContentVerifierProviderBuilder()
                        .setProvider("BC").build(eeAltPubKey);
                if (!csr.isAltSignatureValid(eeAltVerifier)) {
                    System.err.println("Error: CSR alternative signature (alt proof of possession) is invalid.");
                    return 1;
                }

                // Step 11: Build hybrid cert.
                // Add EE alt public key as SubjectAltPublicKeyInfo extension (OID 2.5.29.72), non-critical.
                // Same as CertificateGenerator.generateCertificate() line 227.
                certBuilder.addExtension(Extension.subjectAltPublicKeyInfo, false,
                        SubjectAltPublicKeyInfo.getInstance(eeAltPubKey.getEncoded()));
                ContentSigner altSigner = new JcaContentSignerBuilder(altSigAlgo)
                        .setProvider("BC").build(caAltPrivateKey);
                // 3-arg build: primary signer, non-critical alt sig, alt signer.
                // BC-specific: produces OIDs 2.5.29.72/73/74 per IETF LAMPS composite signatures draft.
                // Same pattern as CertificateGenerator.java:240.
                X509CertificateHolder certHolder = certBuilder.build(primarySigner, false, altSigner);

                // Step 12: Post-build sanity check — both sigs must verify before writing any file.
                X509CertificateHolder issuedHolder = new X509CertificateHolder(certHolder.getEncoded());
                certificate = new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate(certHolder);
                try {
                    certificate.verify(caCert.getPublicKey(), "BC");
                } catch (Exception e) {
                    System.err.println("Post-build sanity: primary sig on issued cert invalid: "
                            + e.getMessage());
                    return 1;
                }
                ContentVerifierProvider caAltVerifier = new JcaContentVerifierProviderBuilder()
                        .setProvider("BC").build(caAltPubKey);
                if (!issuedHolder.isAlternativeSignatureValid(caAltVerifier)) {
                    System.err.println("Post-build sanity: alt sig on issued cert invalid.");
                    return 1;
                }

                altSigAlgoForOutput = altSigAlgo;
                isHybridIssued = true;

            } else {
                // === NON-HYBRID PATH — unchanged behavior ===
                X509CertificateHolder certHolder = certBuilder.build(primarySigner);
                certificate = new JcaX509CertificateConverter()
                        .setProvider("BC").getCertificate(certHolder);
            }

            long signMs = System.currentTimeMillis() - t0;

            // Only save to disk after all verification passes
            CertificateGenerator.saveCertificateToFile(prefixed("certificate.pem"), certificate);

            System.out.println("Signed certificate saved successfully!");
            System.out.println("  Subject:    " + subject);
            System.out.println("  Issuer:     " + issuer);
            System.out.println("  Sig Alg:    " + sigAlgo);
            if (isHybridIssued) {
                System.out.println("  Alt Sig Alg: " + altSigAlgoForOutput);
                System.out.println("  Type:       Hybrid (X.509 alt-signature extensions 2.5.29.72/73/74)");
                System.out.println("  NOTE: Alt-signature extensions (OIDs 2.5.29.72/73/74) are defined in");
                System.out.println("        ITU-T X.509 / ISO/IEC 9594-8 (alternate-signature mechanism).");
                System.out.println("        Not the same as the composite-signatures IETF draft.");
                System.out.println("        Verified with BC-specific API only (not portable JCA behavior).");
            }
            System.out.println("  Valid until:" + notAfter);
            System.out.println("  File:       " + prefixed("certificate.pem"));
            if (printTiming) {
                System.out.println("  Sign time:  " + signMs + " ms");
            }
            System.out.println(certificate);
            return 0;

        } catch (Exception e) {
            System.err.println("Error during signing: " + e.getMessage());
            return 1;
        }
    }

    private static PrivateKey loadPrivKey(String keyFile) throws Exception {
        try (PEMParser pem = new PEMParser(new FileReader(keyFile))) {
            Object obj = pem.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
                return converter.getKeyPair((PEMKeyPair) obj).getPrivate();
            } else if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                throw new IllegalArgumentException(
                        "Encrypted PKCS#8 keys are not supported. Use unencrypted private key.");
            } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) obj);
            } else {
                throw new IllegalArgumentException("Unrecognized PEM object type: "
                        + (obj == null ? "null" : obj.getClass().getName()));
            }
        }
    }

    /**
     * Derives the signing algorithm from the CA cert's own subject public key.
     * Using caCert.getSigAlgName() would return the *parent's* signing algorithm,
     * which breaks cross-type chains (e.g., RSA root issuing an EC intermediate).
     */
    static String deriveSigAlgoFromCaKey(X509Certificate caCert) {
        PublicKey pub = caCert.getPublicKey();
        // Composite: self-signed only in this tool, so sigAlgName is correct
        if (pub instanceof CompositePublicKey) {
            return caCert.getSigAlgName();
        }
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pub.getEncoded());
        String oid = spki.getAlgorithm().getAlgorithm().getId();
        switch (oid) {
            case "1.2.840.113549.1.1.1": { // RSA
                int bits = ((java.security.interfaces.RSAPublicKey) pub).getModulus().bitLength();
                String base = bits >= 4096 ? "SHA512withRSA" : bits >= 3072 ? "SHA384withRSA" : "SHA256withRSA";
                if (caCert.getSigAlgName().toUpperCase().contains("MGF1")) base = base + "andMGF1";
                return base;
            }
            case "1.2.840.10045.2.1": { // EC — curve OID in AlgorithmIdentifier.parameters
                String curveOid = ASN1ObjectIdentifier.getInstance(spki.getAlgorithm().getParameters()).getId();
                if ("1.3.132.0.34".equals(curveOid)) return "SHA384withECDSA"; // secp384r1
                if ("1.3.132.0.35".equals(curveOid)) return "SHA512withECDSA"; // secp521r1
                return "SHA256withECDSA"; // secp256r1 and others
            }
            case "1.3.101.112": return "Ed25519";
            case "1.3.101.113": return "Ed448";
            case "1.2.840.10040.4.1": return "SHA256withDSA"; // DSA
            case "2.16.840.1.101.3.4.3.17": return "ML-DSA-44";
            case "2.16.840.1.101.3.4.3.18": return "ML-DSA-65";
            case "2.16.840.1.101.3.4.3.19": return "ML-DSA-87";
            case "2.16.840.1.101.3.4.3.20": return "SLH-DSA-SHA2-128s";
            case "2.16.840.1.101.3.4.3.21": return "SLH-DSA-SHA2-128f";
            case "2.16.840.1.101.3.4.3.22": return "SLH-DSA-SHA2-192s";
            case "2.16.840.1.101.3.4.3.23": return "SLH-DSA-SHA2-192f";
            case "2.16.840.1.101.3.4.3.24": return "SLH-DSA-SHA2-256s";
            case "2.16.840.1.101.3.4.3.25": return "SLH-DSA-SHA2-256f";
            case "2.16.840.1.101.3.4.3.26": return "SLH-DSA-SHAKE-128s";
            case "2.16.840.1.101.3.4.3.27": return "SLH-DSA-SHAKE-128f";
            case "2.16.840.1.101.3.4.3.28": return "SLH-DSA-SHAKE-192s";
            case "2.16.840.1.101.3.4.3.29": return "SLH-DSA-SHAKE-192f";
            case "2.16.840.1.101.3.4.3.30": return "SLH-DSA-SHAKE-256s";
            case "2.16.840.1.101.3.4.3.31": return "SLH-DSA-SHAKE-256f";
            default:
                return caCert.getSigAlgName(); // fallback
        }
    }

    private static PKCS10CertificationRequest loadCsr(String csrFilePath) throws Exception {
        try (PEMParser pem = new PEMParser(new FileReader(csrFilePath))) {
            Object obj = pem.readObject();
            if (obj instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) obj;
            } else if (obj instanceof CertificationRequest) {
                return new PKCS10CertificationRequest((CertificationRequest) obj);
            } else {
                throw new IllegalArgumentException("Not a CSR: "
                        + (obj == null ? "null" : obj.getClass().getName()));
            }
        }
    }
}
