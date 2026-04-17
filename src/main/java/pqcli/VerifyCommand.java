package pqcli;

import org.bouncycastle.asn1.x509.AltSignatureAlgorithm;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;

@Command(name = "verify", description = "Verify an X.509 certificate signature")
public class VerifyCommand implements Callable<Integer> {

    @Option(names = {"-in"}, required = true, description = "Certificate to verify (PEM)")
    private String certFile;

    @Option(names = {"-CAfile"}, description = "CA certificate for chain verification (omit for self-signed)")
    private String caFile;

    @Override
    public Integer call() {
        ProviderSetup.setupProvider();
        try {
            X509Certificate cert = ViewCommand.loadCertificate(certFile);

            // Keep caCert accessible for alt-key extraction later
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

            // Hybrid alt-signature verification.
            // Uses BC-specific public APIs: X509CertificateHolder.isAlternativeSignatureValid(),
            // SubjectAltPublicKeyInfo, AltSignatureAlgorithm. These are not part of JCA.
            // OIDs 2.5.29.72/73/74 are the X.509 alternate-signature extension OIDs defined in
            // ITU-T X.509 / ISO/IEC 9594-8. They are NOT from the IETF composite-signatures draft,
            // which is a separate mechanism with different algorithm identifiers.
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
                // SubjectAltPublicKeyInfo has the same ASN.1 structure as SubjectPublicKeyInfo
                // (SEQUENCE { AlgorithmIdentifier, BIT STRING }), so the primitive cast is safe.
                SubjectPublicKeyInfo altSpki = SubjectPublicKeyInfo.getInstance(altKeyInfo.toASN1Primitive());
                java.security.PublicKey altPublicKey = new JcaPEMKeyConverter()
                        .setProvider("BC").getPublicKey(altSpki);

                AltSignatureAlgorithm altSigAlgoExt = AltSignatureAlgorithm.fromExtensions(exts);
                if (altSigAlgoExt == null) {
                    System.err.println("Alt Signature:     FAIL: could not parse AltSignatureAlgorithm");
                    return 1;
                }
                String altAlgoOid  = altSigAlgoExt.getAlgorithm().getAlgorithm().getId();
                String altAlgoName = ViewCommand.oidToName(altAlgoOid);  // falls back to OID if unknown

                // For chain verification: the AltSignatureValue is produced by the issuer's alt private key,
                // so verification must use the issuer's alt public key (from the CA cert's
                // SubjectAltPublicKeyInfo extension), not the subject cert's own SubjectAltPublicKeyInfo.
                // For self-signed certs (no -CAfile), the subject IS the issuer, so the cert's own
                // SubjectAltPublicKeyInfo is correct.
                java.security.PublicKey altVerifyKey = altPublicKey; // default: self-signed
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
            // altExtCount == 0: non-hybrid certificate, no alt verification needed.

            return 0;

        } catch (java.security.SignatureException | java.security.cert.CertificateException e) {
            System.err.println("Primary Signature: FAIL: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }
}
