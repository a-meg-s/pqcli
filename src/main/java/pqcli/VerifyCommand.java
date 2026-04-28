package pqcli;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AltSignatureAlgorithm;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(name = "verify", description = "Verify an X.509 certificate signature")
public class VerifyCommand implements Callable<Integer> {

    @Option(names = {"-in"}, required = true, description = "Certificate to verify (PEM)")
    private String certFile;

    @Option(names = {"-CAfile"}, description = "CA certificate for one-link signature verification (omit for self-signed)")
    private String caFile;

    @Option(names = {"-chain"}, description = "Intermediate CA certificate for full chain verification (PEM)")
    private String chainFile;

    @Option(names = {"-trust"}, description = "Trust anchor certificate for full chain verification (PEM)")
    private String trustFile;

    @Option(names = {"--related-cert"},
            description = {
                "Check RelatedCertificate extension hash binding (RFC 9763, OID 1.3.6.1.5.5.7.1.36).",
                "Hash-binding check only — does not re-verify CSR PoP or certificate chain.",
                "Cannot be combined with -CAfile, -chain, or -trust."
            })
    private String relatedCertFile;

    @Override
    public Integer call() {
        ProviderSetup.setupProvider();
        try {
            // Mode conflict checks
            if (caFile != null && (chainFile != null || trustFile != null)) {
                System.err.println("Error: -CAfile and -chain/-trust cannot be combined; use one verification mode only.");
                return 1;
            }
            if ((chainFile != null) != (trustFile != null)) {
                System.err.println("Error: Use -in with -CAfile for one-link verification, or provide both -chain and -trust for chain verification.");
                return 1;
            }
            if (relatedCertFile != null && (caFile != null || chainFile != null || trustFile != null)) {
                System.err.println("Error: --related-cert cannot be combined with -CAfile, -chain, or -trust.");
                System.err.println("       Verify each cert chain separately after checking the binding.");
                return 1;
            }

            // Mode B: full 3-tier chain verification
            if (chainFile != null && trustFile != null) {
                return verifyChain();
            }

            // Mode C: RelatedCertificate hash-binding check (RFC 9763 Stage 2 test mode)
            if (relatedCertFile != null) {
                return verifyRelatedCertBinding();
            }

            // Mode A: one-link signature verification (unchanged behavior)
            X509Certificate cert = ViewCommand.loadCertificate(certFile);

            X509Certificate caCert = null;
            java.security.PublicKey verifyKey;
            if (caFile != null) {
                caCert = ViewCommand.loadCertificate(caFile);
                verifyKey = caCert.getPublicKey();
            } else {
                verifyKey = cert.getPublicKey();
            }

            cert.verify(verifyKey, "BC");

            System.out.println("Primary Signature: OK");
            System.out.println("  Subject:  " + cert.getSubjectX500Principal().getName());
            System.out.println("  Issuer:   " + cert.getIssuerX500Principal().getName());
            System.out.println("  Sig Alg:  " + cert.getSigAlgName());

            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            Extensions exts = holder.getExtensions();
            boolean hasAltKey   = exts != null && exts.getExtension(Extension.subjectAltPublicKeyInfo) != null;
            boolean hasAltAlgo  = exts != null && exts.getExtension(Extension.altSignatureAlgorithm)   != null;
            boolean hasAltValue = exts != null && exts.getExtension(Extension.altSignatureValue)        != null;
            int altExtCount = (hasAltKey ? 1 : 0) + (hasAltAlgo ? 1 : 0) + (hasAltValue ? 1 : 0);

            if (altExtCount == 3) {
                SubjectAltPublicKeyInfo altKeyInfo = SubjectAltPublicKeyInfo.fromExtensions(exts);
                if (altKeyInfo == null) {
                    System.err.println("Alt Signature:     FAIL: could not parse SubjectAltPublicKeyInfo");
                    return 1;
                }
                SubjectPublicKeyInfo altSpki = SubjectPublicKeyInfo.getInstance(altKeyInfo.toASN1Primitive());
                java.security.PublicKey altPublicKey = new JcaPEMKeyConverter()
                        .setProvider("BC").getPublicKey(altSpki);

                AltSignatureAlgorithm altSigAlgoExt = AltSignatureAlgorithm.fromExtensions(exts);
                if (altSigAlgoExt == null) {
                    System.err.println("Alt Signature:     FAIL: could not parse AltSignatureAlgorithm");
                    return 1;
                }
                String altAlgoOid  = altSigAlgoExt.getAlgorithm().getAlgorithm().getId();
                String altAlgoName = ViewCommand.oidToName(altAlgoOid);

                java.security.PublicKey altVerifyKey = altPublicKey;
                if (caCert != null) {
                    X509CertificateHolder caHolder = new X509CertificateHolder(caCert.getEncoded());
                    SubjectAltPublicKeyInfo caAltKeyInfo = SubjectAltPublicKeyInfo.fromExtensions(
                            caHolder.getExtensions());
                    if (caAltKeyInfo != null) {
                        SubjectPublicKeyInfo caAltSpki = SubjectPublicKeyInfo.getInstance(
                                caAltKeyInfo.toASN1Primitive());
                        altVerifyKey = new JcaPEMKeyConverter().setProvider("BC")
                                .getPublicKey(caAltSpki);
                    }
                }

                ContentVerifierProvider altProvider = new JcaContentVerifierProviderBuilder()
                        .setProvider("BC").build(altVerifyKey);

                boolean altValid;
                try {
                    altValid = holder.isAlternativeSignatureValid(altProvider);
                } catch (CertException e) {
                    System.err.println("Alt Signature:     FAIL: " + e.getMessage());
                    return 1;
                }
                if (!altValid) {
                    System.err.println("Alt Signature:     FAIL: verification returned false");
                    return 1;
                }
                System.out.println("Alt Signature:     OK");
                System.out.println("  Alt Pub Key:  " + altPublicKey.getAlgorithm() +
                        (caCert != null ? " (subject) / verified via CA cert alt key" : ""));
                System.out.println("  Alt Sig Alg:  " + altAlgoName + "  (OID: " + altAlgoOid + ")");
                System.out.println("  NOTE: Verified using BC-specific public API, not JCA.");
                System.out.println("        OIDs 2.5.29.72/73/74 are X.509 alternate-signature extension OIDs");
                System.out.println("        (ITU-T X.509 / ISO/IEC 9594-8). Not the composite-signatures draft.");

            } else if (altExtCount > 0) {
                System.err.println("Alt Signature:     FAIL: incomplete hybrid extensions " +
                        "(expected OIDs 2.5.29.72/73/74, found " + altExtCount + "/3)");
                System.err.println("  Missing: " +
                        (!hasAltKey   ? "2.5.29.72 (SubjectAltPublicKeyInfo) " : "") +
                        (!hasAltAlgo  ? "2.5.29.73 (AltSignatureAlgorithm) "  : "") +
                        (!hasAltValue ? "2.5.29.74 (AltSignatureValue)"        : ""));
                return 1;
            }

            return 0;

        } catch (java.security.SignatureException | java.security.cert.CertificateException e) {
            System.err.println("Primary Signature: FAIL: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }

    // =========================================================================
    // Mode B: full 3-tier chain verification with semantic PKI checks
    // =========================================================================

    private int verifyChain() {
        try {
            X509Certificate leaf         = ViewCommand.loadCertificate(certFile);
            X509Certificate intermediate = ViewCommand.loadCertificate(chainFile);
            X509Certificate trust        = ViewCommand.loadCertificate(trustFile);

            boolean allPassed = true;

            System.out.println("Chain verification:");
            System.out.println("  Trust anchor: " + trust.getSubjectX500Principal().getName());
            System.out.println("  Intermediate: " + intermediate.getSubjectX500Principal().getName());
            System.out.println("  Leaf:         " + leaf.getSubjectX500Principal().getName());
            System.out.println();

            // ---- Structural checks ----

            if (!trust.getIssuerX500Principal().equals(trust.getSubjectX500Principal())) {
                System.err.println("FAIL: Trust anchor is not self-signed (issuer != subject)");
                allPassed = false;
            }
            if (!intermediate.getIssuerX500Principal().equals(trust.getSubjectX500Principal())) {
                System.err.println("FAIL: Issuer/subject DN mismatch: intermediate issuer "
                        + intermediate.getIssuerX500Principal().getName()
                        + " != trust subject " + trust.getSubjectX500Principal().getName());
                allPassed = false;
            }
            if (!leaf.getIssuerX500Principal().equals(intermediate.getSubjectX500Principal())) {
                System.err.println("FAIL: Issuer/subject DN mismatch: leaf issuer "
                        + leaf.getIssuerX500Principal().getName()
                        + " != intermediate subject " + intermediate.getSubjectX500Principal().getName());
                allPassed = false;
            }

            // ---- Cryptographic: primary signatures ----

            try {
                trust.verify(trust.getPublicKey(), "BC");
                System.out.println("LINK 1 (trust self-sig):            OK");
            } catch (Exception e) {
                System.err.println("FAIL [LINK 1]: Trust anchor self-signature invalid: " + e.getMessage());
                allPassed = false;
            }

            try {
                intermediate.verify(trust.getPublicKey(), "BC");
                System.out.println("LINK 2 (intermediate <- trust):     OK");
            } catch (Exception e) {
                System.err.println("FAIL [LINK 2]: Intermediate signature invalid: " + e.getMessage());
                allPassed = false;
            }

            try {
                leaf.verify(intermediate.getPublicKey(), "BC");
                System.out.println("LINK 3 (leaf <- intermediate):      OK");
            } catch (Exception e) {
                System.err.println("FAIL [LINK 3]: Leaf signature invalid: " + e.getMessage());
                allPassed = false;
            }

            // ---- Hybrid alt-sig checks ----

            allPassed &= checkHybridAltSigLink(trust, trust,               "LINK 1 hybrid alt-sig");
            allPassed &= checkHybridAltSigLink(intermediate, trust,        "LINK 2 hybrid alt-sig");
            allPassed &= checkHybridAltSigLink(leaf,         intermediate, "LINK 3 hybrid alt-sig");

            // ---- Validity dates ----

            for (X509Certificate cert : new X509Certificate[]{trust, intermediate, leaf}) {
                String name = cert.getSubjectX500Principal().getName();
                try {
                    cert.checkValidity();
                } catch (java.security.cert.CertificateExpiredException e) {
                    System.err.println("FAIL: Certificate is expired: " + name);
                    allPassed = false;
                } catch (java.security.cert.CertificateNotYetValidException e) {
                    System.err.println("FAIL: Certificate is not yet valid: " + name);
                    allPassed = false;
                }
            }

            // ---- BasicConstraints ----

            if (trust.getBasicConstraints() < 0) {
                System.err.println("FAIL: Trust anchor is not a CA certificate (BasicConstraints CA=true required)");
                allPassed = false;
            }
            if (intermediate.getBasicConstraints() < 0) {
                System.err.println("FAIL: Intermediate is not a CA certificate (BasicConstraints CA=true required)");
                allPassed = false;
            }
            if (leaf.getBasicConstraints() >= 0) {
                System.err.println("FAIL: Leaf certificate unexpectedly has CA=true");
                allPassed = false;
            }

            // ---- KeyUsage ----

            boolean[] trustKu = trust.getKeyUsage();
            if (trustKu != null && !trustKu[5]) {
                System.err.println("FAIL: Trust anchor does not have keyCertSign in KeyUsage");
                allPassed = false;
            }
            boolean[] intKu = intermediate.getKeyUsage();
            if (intKu != null && !intKu[5]) {
                System.err.println("FAIL: Intermediate does not have keyCertSign in KeyUsage");
                allPassed = false;
            }

            // ---- PathLen ----
            // Root -> intermediate -> leaf: 1 intermediate CA follows the root.
            // pathLen=0 on root means zero intermediates allowed -> fail.
            int rootPathLen = trust.getBasicConstraints();
            if (rootPathLen >= 0 && rootPathLen < 1) {
                System.err.println("FAIL: Path length constraint violated: trust anchor has pathLen="
                        + rootPathLen + " but 1 intermediate CA follows");
                allPassed = false;
            }
            // Intermediate's pathLen: only a leaf follows — any pathLen >= 0 is valid.

            // ---- SKID/AKID linkage ----

            allPassed &= checkSkidAkidLinkage(intermediate, trust,        "intermediate <- trust");
            allPassed &= checkSkidAkidLinkage(leaf,         intermediate, "leaf <- intermediate");

            // ---- Hybrid extension completeness ----

            allPassed &= checkHybridCompleteness(trust);
            allPassed &= checkHybridCompleteness(intermediate);
            allPassed &= checkHybridCompleteness(leaf);

            // ---- Unsupported critical extensions ----

            Set<String> knownCritical = new HashSet<>(Arrays.asList(
                    Extension.basicConstraints.getId(),
                    Extension.keyUsage.getId()
            ));
            for (X509Certificate cert : new X509Certificate[]{trust, intermediate, leaf}) {
                Set<String> critOids = cert.getCriticalExtensionOIDs();
                if (critOids != null) {
                    for (String oid : critOids) {
                        if (!knownCritical.contains(oid)) {
                            System.err.println("FAIL: Unsupported critical extension: " + oid
                                    + " in " + cert.getSubjectX500Principal().getName());
                            allPassed = false;
                        }
                    }
                }
            }

            System.out.println();
            System.out.println("Chain verification: " + (allPassed ? "PASSED" : "FAILED"));
            System.out.println("Revocation: not checked (out of scope)");

            return allPassed ? 0 : 1;

        } catch (Exception e) {
            System.err.println("Error during chain verification: " + e.getMessage());
            return 1;
        }
    }

    // =========================================================================
    // Mode C: RelatedCertificate hash-binding check (RFC 9763 Stage 2 test mode)
    // =========================================================================

    private int verifyRelatedCertBinding() {
        try {
            X509Certificate cert        = ViewCommand.loadCertificate(certFile);
            X509Certificate relatedCert = ViewCommand.loadCertificate(relatedCertFile);

            System.out.println("RFC 9763 RelatedCertificate hash-binding check");
            System.out.println("  In cert:      " + cert.getSubjectX500Principal().getName());
            System.out.println("  Related cert: " + relatedCert.getSubjectX500Principal().getName());
            System.out.println();

            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            Extensions exts = holder.getExtensions();
            org.bouncycastle.asn1.x509.Extension relatedExt = exts == null ? null
                    : exts.getExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.36"));
            if (relatedExt == null) {
                System.err.println("FAIL: No RelatedCertificate extension (OID 1.3.6.1.5.5.7.1.36) in -in cert.");
                return 1;
            }

            // RelatedCertificate ::= SEQUENCE { hashAlgorithm DigestAlgorithmIdentifier, hashValue OCTET STRING }
            ASN1Sequence seq = ASN1Sequence.getInstance(relatedExt.getParsedValue());
            AlgorithmIdentifier hashAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            byte[] expectedHash = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
            String algOid = hashAlgId.getAlgorithm().getId();

            String jcaAlgName;
            switch (algOid) {
                case "2.16.840.1.101.3.4.2.1": jcaAlgName = "SHA-256"; break;
                case "2.16.840.1.101.3.4.2.2": jcaAlgName = "SHA-384"; break;
                default:
                    System.err.println("FAIL: Unsupported hash algorithm OID in RelatedCertificate extension: " + algOid);
                    return 1;
            }

            byte[] actualHash = MessageDigest.getInstance(jcaAlgName).digest(relatedCert.getEncoded());

            String algName = ViewCommand.oidToName(algOid);
            System.out.println("Binding (-in → related):");
            System.out.println("  Hash Alg:  " + algName + "  (OID: " + algOid + ")");
            System.out.println("  Expected:  " + ViewCommand.bytesToHex(expectedHash) + "  (" + expectedHash.length + " bytes)");
            System.out.println("  Actual:    " + ViewCommand.bytesToHex(actualHash)   + "  (" + actualHash.length   + " bytes)");

            boolean match = Arrays.equals(expectedHash, actualHash);
            System.out.println("  Result:    " + (match ? "OK" : "FAIL — hash mismatch"));
            System.out.println();
            System.out.println("NOTE: This verifies only the hash binding.");
            System.out.println("      No relatedCertRequest PoP was verified (Stage 2 test mode only).");
            System.out.println("      Chain validity: verify each cert separately with -CAfile or -chain/-trust.");

            if (!match) System.err.println("FAIL: RelatedCertificate hash mismatch.");
            return match ? 0 : 1;

        } catch (Exception e) {
            System.err.println("Error during RelatedCertificate binding check: " + e.getMessage());
            return 1;
        }
    }

    private boolean checkHybridAltSigLink(X509Certificate subjectCert, X509Certificate issuerCert,
                                           String linkDesc) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(subjectCert.getEncoded());
            Extensions exts = holder.getExtensions();
            boolean hasAltKey   = exts != null && exts.getExtension(Extension.subjectAltPublicKeyInfo) != null;
            boolean hasAltAlgo  = exts != null && exts.getExtension(Extension.altSignatureAlgorithm)   != null;
            boolean hasAltValue = exts != null && exts.getExtension(Extension.altSignatureValue)        != null;

            if (!hasAltKey && !hasAltAlgo && !hasAltValue) return true; // not hybrid

            if (!hasAltKey || !hasAltAlgo || !hasAltValue) {
                System.err.println("FAIL [" + linkDesc + "]: Incomplete hybrid extensions (found "
                        + ((hasAltKey ? 1 : 0) + (hasAltAlgo ? 1 : 0) + (hasAltValue ? 1 : 0)) + "/3)");
                return false;
            }

            // Extract alt verify key from issuer cert's SubjectAltPublicKeyInfo
            X509CertificateHolder issuerHolder = new X509CertificateHolder(issuerCert.getEncoded());
            SubjectAltPublicKeyInfo issuerAltKeyInfo = SubjectAltPublicKeyInfo.fromExtensions(
                    issuerHolder.getExtensions());
            if (issuerAltKeyInfo == null) {
                System.err.println("FAIL [" + linkDesc + "]: Issuer has no SubjectAltPublicKeyInfo — cannot verify hybrid cert");
                return false;
            }
            SubjectPublicKeyInfo issuerAltSpki = SubjectPublicKeyInfo.getInstance(issuerAltKeyInfo.toASN1Primitive());
            java.security.PublicKey altVerifyKey = new JcaPEMKeyConverter().setProvider("BC")
                    .getPublicKey(issuerAltSpki);

            ContentVerifierProvider altProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(altVerifyKey);

            boolean valid;
            try {
                valid = holder.isAlternativeSignatureValid(altProvider);
            } catch (CertException e) {
                System.err.println("FAIL [" + linkDesc + "]: Hybrid alt signature: " + e.getMessage());
                return false;
            }
            if (!valid) {
                System.err.println("FAIL [" + linkDesc + "]: Hybrid alt signature verification returned false");
                return false;
            }
            System.out.println(linkDesc + ":    OK");
            return true;

        } catch (Exception e) {
            System.err.println("FAIL [" + linkDesc + "]: Hybrid alt sig check error: " + e.getMessage());
            return false;
        }
    }

    private boolean checkSkidAkidLinkage(X509Certificate subjectCert, X509Certificate issuerCert,
                                          String linkDesc) {
        try {
            X509CertificateHolder subjectHolder = new X509CertificateHolder(subjectCert.getEncoded());
            X509CertificateHolder issuerHolder  = new X509CertificateHolder(issuerCert.getEncoded());

            byte[] issuerSkid = null;
            if (issuerHolder.getExtensions() != null) {
                SubjectKeyIdentifier skidExt = SubjectKeyIdentifier.fromExtensions(issuerHolder.getExtensions());
                if (skidExt != null) issuerSkid = skidExt.getKeyIdentifier();
            }
            byte[] subjectAkidKey = null;
            if (subjectHolder.getExtensions() != null) {
                AuthorityKeyIdentifier akidExt = AuthorityKeyIdentifier.fromExtensions(subjectHolder.getExtensions());
                if (akidExt != null) subjectAkidKey = akidExt.getKeyIdentifier();
            }

            if (issuerSkid == null || subjectAkidKey == null) return true; // absent — skip

            if (!Arrays.equals(issuerSkid, subjectAkidKey)) {
                System.err.println("FAIL: AuthorityKeyIdentifier does not match issuer SubjectKeyIdentifier ("
                        + linkDesc + ")");
                return false;
            }
            return true;
        } catch (Exception e) {
            // Don't fail on parse errors for non-tool-generated certs
            return true;
        }
    }

    private boolean checkHybridCompleteness(X509Certificate cert) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
            Extensions exts = holder.getExtensions();
            boolean hasAltKey   = exts != null && exts.getExtension(Extension.subjectAltPublicKeyInfo) != null;
            boolean hasAltAlgo  = exts != null && exts.getExtension(Extension.altSignatureAlgorithm)   != null;
            boolean hasAltValue = exts != null && exts.getExtension(Extension.altSignatureValue)        != null;
            int count = (hasAltKey ? 1 : 0) + (hasAltAlgo ? 1 : 0) + (hasAltValue ? 1 : 0);
            if (count > 0 && count < 3) {
                System.err.println("FAIL: Incomplete hybrid extensions in "
                        + cert.getSubjectX500Principal().getName() + " (found " + count + "/3)");
                return false;
            }
            return true;
        } catch (Exception e) {
            return true;
        }
    }
}
