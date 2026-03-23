package pqcli;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;

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

            java.security.PublicKey verifyKey;
            if (caFile != null) {
                X509Certificate caCert = ViewCommand.loadCertificate(caFile);
                verifyKey = caCert.getPublicKey();
            } else {
                verifyKey = cert.getPublicKey();
            }

            cert.verify(verifyKey, "BC");

            System.out.println("Signature OK");
            System.out.println("  Subject:  " + cert.getSubjectX500Principal().getName());
            System.out.println("  Issuer:   " + cert.getIssuerX500Principal().getName());
            System.out.println("  Sig Alg:  " + cert.getSigAlgName());

            // Detect hybrid cert and note alt-signature limitation
            try {
                X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
                if (holder.getExtensions() != null &&
                        holder.getExtensions().getExtension(Extension.altSignatureValue) != null) {
                    System.out.println("Note: Hybrid certificate detected (AltSignatureValue present).");
                    System.out.println("      Only primary signature verified. Alt signature (OID 2.5.29.74) " +
                            "verification requires BC internal APIs — not implemented.");
                }
            } catch (Exception ignored) {}

            return 0;

        } catch (java.security.SignatureException | java.security.cert.CertificateException e) {
            System.err.println("Signature FAILED: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        }
    }
}
