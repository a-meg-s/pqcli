package pqcli;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * Industrial benchmark runner: long-lived JVM, providers initialized once,
 * direct-core PKI operations without CLI overhead per iteration.
 *
 * Invoked as: java -cp pqcli-0.1.0.jar pqcli.IndustrialBenchmarkRunner \
 *   --algo "RSA:3072" --algo-tag rsa3072 --operation keygen \
 *   --warmup 5 --iterations 100 \
 *   --out <out_dir> --staging <staging_dir>
 *
 * Writes to <out_dir>:
 *   iterations.csv, warmup_iterations.csv, sizes.csv, runner.log
 */
public class IndustrialBenchmarkRunner {

    private static final String ITER_HEADER =
            "iter_index,warmup,elapsed_ns,elapsed_ms,success,error,execution_model\n";
    private static final String SIZES_HEADER =
            "out_pub_key_pem_bytes,out_pub_key_der_bytes," +
            "out_priv_key_pem_bytes,out_priv_key_der_bytes," +
            "out_alt_pub_pem_bytes,out_alt_pub_der_bytes," +
            "out_alt_priv_pem_bytes,out_alt_priv_der_bytes," +
            "out_cert_pem_bytes,out_cert_der_bytes," +
            "out_csr_pem_bytes,out_csr_der_bytes," +
            "out_int_cert_pem_bytes,out_int_cert_der_bytes," +
            "out_leaf_cert_pem_bytes,out_leaf_cert_der_bytes," +
            "out_chain_total_pem_bytes,out_chain_total_der_bytes\n";

    private static PrintStream quiet;

    public static void main(String[] args) throws Exception {
        quiet = new PrintStream(OutputStream.nullOutputStream());

        // Parse arguments
        String algo = null, algoTag = null, operation = null, outDir = null, stagingDir = null;
        int warmup = 5, iterations = 100;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--algo":        algo      = args[++i]; break;
                case "--algo-tag":    algoTag   = args[++i]; break;
                case "--operation":   operation = args[++i]; break;
                case "--warmup":      warmup    = Integer.parseInt(args[++i]); break;
                case "--iterations":  iterations = Integer.parseInt(args[++i]); break;
                case "--out":         outDir    = args[++i]; break;
                case "--staging":     stagingDir = args[++i]; break;
                case "--help":
                    System.out.println("Usage: IndustrialBenchmarkRunner --algo ALGO --algo-tag TAG --operation OP");
                    System.out.println("  --warmup N --iterations N --out DIR --staging DIR");
                    System.out.println("Operations: keygen cert csr sign-leaf sign-intermediate-ca");
                    System.out.println("  verify-selfsigned verify-issued verify-modeA-chain");
                    System.out.println("  verify-modeB-strict verify-dynamic verify-modeB-direct");
                    System.out.println("  workflow-2tier workflow-3tier");
                    System.exit(0);
            }
        }

        if (algo == null || operation == null || outDir == null || stagingDir == null) {
            System.err.println("Error: --algo, --operation, --out, --staging are required");
            System.exit(1);
        }

        Path out = Paths.get(outDir);
        Path staging = Paths.get(stagingDir);
        Files.createDirectories(out);
        Files.createDirectories(staging);

        // Initialize providers once — not timed
        ProviderSetup.setupProvider();

        AlgorithmSet algorithmSet = new AlgorithmSet(algo);

        // Pre-generation — not timed
        System.out.println("[BENCH] pregen: " + algoTag + "/" + operation);
        boolean pregenOk = pregen(algorithmSet, algo, algoTag, operation, staging);
        if (!pregenOk) {
            System.err.println("[BENCH] pregen FAILED for " + algoTag + "/" + operation);
            System.exit(1);
        }

        System.out.println("[BENCH] starting " + operation + ": warmup=" + warmup + " iterations=" + iterations);

        try (PrintWriter measuredWriter = new PrintWriter(new FileWriter(out.resolve("iterations.csv").toFile()));
             PrintWriter warmupWriter   = new PrintWriter(new FileWriter(out.resolve("warmup_iterations.csv").toFile()))) {

            measuredWriter.print(ITER_HEADER);
            warmupWriter.print(ITER_HEADER);

            long[] lastNs = {0};
            String lastError = "";
            long[] lastSizes = null;

            int total = warmup + iterations;
            for (int idx = 0; idx < total; idx++) {
                boolean isWarmup = idx < warmup;
                int iterIdx = isWarmup ? idx : idx - warmup;

                IterResult r = runIteration(algorithmSet, algo, algoTag, operation, staging, out, iterIdx);

                String row = iterIdx + "," + (isWarmup ? 1 : 0) + "," +
                        r.elapsedNs + "," + String.format("%.4f", r.elapsedNs / 1_000_000.0) + "," +
                        (r.success ? 1 : 0) + "," + escapeCsv(r.error) + "," +
                        execModel(operation) + "\n";

                if (isWarmup) {
                    warmupWriter.print(row);
                } else {
                    measuredWriter.print(row);
                    if (r.success) {
                        lastSizes = r.sizes;
                    }
                }
            }

            measuredWriter.flush();
            warmupWriter.flush();

            // Write sizes from last successful measured iteration
            if (lastSizes != null) {
                writeSizes(out.resolve("sizes.csv"), lastSizes);
            } else {
                writeSizes(out.resolve("sizes.csv"), new long[18]);
            }
        }

        System.out.println("[BENCH] done: " + algoTag + "/" + operation);
    }

    // ── Operation dispatch ────────────────────────────────────────────────────

    private static IterResult runIteration(AlgorithmSet algorithmSet, String algo,
            String algoTag, String op, Path staging, Path out, int iterIdx) {
        long t0 = System.nanoTime();
        try {
            long[] sizes = doOperation(algorithmSet, algo, algoTag, op, staging, out, iterIdx);
            long elapsed = System.nanoTime() - t0;
            return new IterResult(elapsed, true, "", sizes);
        } catch (Exception e) {
            long elapsed = System.nanoTime() - t0;
            return new IterResult(elapsed, false, e.getMessage() != null ? e.getMessage() : e.getClass().getName(), null);
        }
    }

    private static long[] doOperation(AlgorithmSet algorithmSet, String algo,
            String algoTag, String op, Path staging, Path out, int iterIdx) throws Exception {
        String pfx = out.resolve("iter").toString();
        switch (op) {
            case "keygen":              return doKeygen(algorithmSet, pfx);
            case "cert":                return doCert(algorithmSet, algoTag, pfx);
            case "csr":                 return doCsr(algorithmSet, algoTag, pfx);
            case "sign-leaf":           return doSign(algorithmSet, staging, pfx, CertificateProfile.LEAF);
            case "sign-intermediate-ca":return doSign(algorithmSet, staging, pfx, CertificateProfile.INTERMEDIATE_CA);
            case "verify-selfsigned":   return doVerifySelfsigned(staging);
            case "verify-issued":       return doVerifyIssued(staging);
            case "verify-modeA-chain":  return doVerifyModeAChain(staging);
            case "verify-modeB-strict": return doVerifyModeBStrict(staging);
            case "verify-dynamic":      return doVerifyDynamic(staging);
            case "verify-modeB-direct": return doVerifyModeBDirect(staging);
            case "workflow-2tier":      return doWorkflow2tier(algorithmSet, algoTag, staging, out);
            case "workflow-3tier":      return doWorkflow3tier(algorithmSet, algoTag, staging, out);
            default: throw new IllegalArgumentException("Unknown operation: " + op);
        }
    }

    // ── keygen ────────────────────────────────────────────────────────────────

    private static long[] doKeygen(AlgorithmSet algorithmSet, String pfx) throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyGenerator.saveKeyToFile(pfx + "_private_key.pem", kp.getPrivate());
        KeyGenerator.saveKeyToFile(pfx + "_public_key.pem", kp.getPublic());
        long pubPem = pemSize(pfx + "_public_key.pem"), pubDer = kp.getPublic().getEncoded().length;
        long privPem = pemSize(pfx + "_private_key.pem"), privDer = kp.getPrivate().getEncoded().length;
        long altPubPem = 0, altPubDer = 0, altPrivPem = 0, altPrivDer = 0;
        if (algorithmSet.isHybrid()) {
            KeyPair altKp = KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms());
            KeyGenerator.saveKeyToFile(pfx + "_alt_private_key.pem", altKp.getPrivate());
            KeyGenerator.saveKeyToFile(pfx + "_alt_public_key.pem", altKp.getPublic());
            altPubPem = pemSize(pfx + "_alt_public_key.pem"); altPubDer = altKp.getPublic().getEncoded().length;
            altPrivPem = pemSize(pfx + "_alt_private_key.pem"); altPrivDer = altKp.getPrivate().getEncoded().length;
        }
        return sizes(pubPem, pubDer, privPem, privDer, altPubPem, altPubDer, altPrivPem, altPrivDer,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    // ── cert ──────────────────────────────────────────────────────────────────

    private static long[] doCert(AlgorithmSet algorithmSet, String algoTag, String pfx) throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair altKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate cert = CertificateGenerator.generateCertificate(
                algorithmSet, kp, altKp, "CN=Bench-" + algoTag, 365.0);
        KeyGenerator.saveKeyToFile(pfx + "_private_key.pem", kp.getPrivate());
        KeyGenerator.saveKeyToFile(pfx + "_public_key.pem", kp.getPublic());
        if (altKp != null) {
            KeyGenerator.saveKeyToFile(pfx + "_alt_private_key.pem", altKp.getPrivate());
            KeyGenerator.saveKeyToFile(pfx + "_alt_public_key.pem", altKp.getPublic());
        }
        CertificateGenerator.saveCertificateToFile(pfx + "_certificate.pem", cert);
        long certPem = pemSize(pfx + "_certificate.pem"), certDer = cert.getEncoded().length;
        long pubPem = pemSize(pfx + "_public_key.pem"), pubDer = kp.getPublic().getEncoded().length;
        long privPem = pemSize(pfx + "_private_key.pem"), privDer = kp.getPrivate().getEncoded().length;
        long altPubPem = 0, altPubDer = 0, altPrivPem = 0, altPrivDer = 0;
        if (altKp != null) {
            altPubPem  = pemSize(pfx + "_alt_public_key.pem");  altPubDer  = altKp.getPublic().getEncoded().length;
            altPrivPem = pemSize(pfx + "_alt_private_key.pem"); altPrivDer = altKp.getPrivate().getEncoded().length;
        }
        return sizes(pubPem, pubDer, privPem, privDer, altPubPem, altPubDer, altPrivPem, altPrivDer,
                certPem, certDer, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    // ── csr ───────────────────────────────────────────────────────────────────

    private static long[] doCsr(AlgorithmSet algorithmSet, String algoTag, String pfx) throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        X500Name subject = new X500Name("CN=Bench-" + algoTag);
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        PKCS10CertificationRequest csr;
        long altPubPem = 0, altPubDer = 0, altPrivPem = 0, altPrivDer = 0;
        if (algorithmSet.isHybrid()) {
            KeyPair altKp = KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms());
            ContentSigner primary = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), kp);
            ContentSigner alt = CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), altKp);
            csr = builder.build(primary, altKp.getPublic(), alt);
            KeyGenerator.saveKeyToFile(pfx + "_alt_private_key.pem", altKp.getPrivate());
            KeyGenerator.saveKeyToFile(pfx + "_alt_public_key.pem", altKp.getPublic());
            altPubPem  = pemSize(pfx + "_alt_public_key.pem");  altPubDer  = altKp.getPublic().getEncoded().length;
            altPrivPem = pemSize(pfx + "_alt_private_key.pem"); altPrivDer = altKp.getPrivate().getEncoded().length;
        } else {
            ContentSigner signer = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), kp);
            csr = builder.build(signer);
        }
        KeyGenerator.saveKeyToFile(pfx + "_private_key.pem", kp.getPrivate());
        KeyGenerator.saveKeyToFile(pfx + "_public_key.pem", kp.getPublic());
        CSRCommand.saveCsrToFile(pfx + "_csr.pem", csr);
        long pubPem = pemSize(pfx + "_public_key.pem"), pubDer = kp.getPublic().getEncoded().length;
        long privPem = pemSize(pfx + "_private_key.pem"), privDer = kp.getPrivate().getEncoded().length;
        long csrPem = pemSize(pfx + "_csr.pem"), csrDer = csr.getEncoded().length;
        return sizes(pubPem, pubDer, privPem, privDer, altPubPem, altPubDer, altPrivPem, altPrivDer,
                0, 0, csrPem, csrDer, 0, 0, 0, 0, 0, 0);
    }

    // ── sign-leaf / sign-intermediate-ca ──────────────────────────────────────

    private static long[] doSign(AlgorithmSet algorithmSet, Path staging, String pfx,
            CertificateProfile profile) throws Exception {
        PKCS10CertificationRequest csr = SignCommand.loadCsr(staging.resolve("ee_csr.pem").toString());
        X509Certificate caCert = ViewCommand.loadCertificate(staging.resolve("ca_certificate.pem").toString());
        PrivateKey caKey = SignCommand.loadPrivKey(staging.resolve("ca_private_key.pem").toString());
        PrivateKey caAltKey = null;
        Path altKeyPath = staging.resolve("ca_alt_private_key.pem");
        if (algorithmSet.isHybrid() && Files.exists(altKeyPath)) {
            caAltKey = SignCommand.loadPrivKey(altKeyPath.toString());
        }
        X509Certificate signed = SignCommand.signCsr(csr, caCert, caKey, caAltKey, profile, 365);
        CertificateGenerator.saveCertificateToFile(pfx + "_certificate.pem", signed);
        long certPem = pemSize(pfx + "_certificate.pem"), certDer = signed.getEncoded().length;
        return sizes(0, 0, 0, 0, 0, 0, 0, 0, certPem, certDer, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    // ── verify operations ─────────────────────────────────────────────────────

    private static long[] doVerifySelfsigned(Path staging) throws Exception {
        X509Certificate cert = ViewCommand.loadCertificate(staging.resolve("cert_certificate.pem").toString());
        int rc = VerifyCommand.verifyModeA(cert, null, quiet);
        if (rc != 0) throw new RuntimeException("verify-selfsigned failed");
        long certPem = pemSize(staging.resolve("cert_certificate.pem").toString());
        long certDer = cert.getEncoded().length;
        return sizes(0, 0, 0, 0, 0, 0, 0, 0, certPem, certDer, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    private static long[] doVerifyIssued(Path staging) throws Exception {
        X509Certificate leaf = ViewCommand.loadCertificate(staging.resolve("vcert_leaf_certificate.pem").toString());
        X509Certificate ca   = ViewCommand.loadCertificate(staging.resolve("vcert_ca_certificate.pem").toString());
        int rc = VerifyCommand.verifyModeA(leaf, ca, quiet);
        if (rc != 0) throw new RuntimeException("verify-issued failed");
        return sizes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, pemSize(staging.resolve("vcert_leaf_certificate.pem").toString()), leaf.getEncoded().length, 0, 0);
    }

    private static long[] doVerifyModeAChain(Path staging) throws Exception {
        X509Certificate leaf = ViewCommand.loadCertificate(staging.resolve("cv_leaf_certificate.pem").toString());
        X509Certificate intm = ViewCommand.loadCertificate(staging.resolve("cv_int_certificate.pem").toString());
        X509Certificate root = ViewCommand.loadCertificate(staging.resolve("cv_root_certificate.pem").toString());
        int rc1 = VerifyCommand.verifyModeA(leaf, intm, quiet);
        int rc2 = VerifyCommand.verifyModeA(intm, root, quiet);
        if (rc1 != 0 || rc2 != 0) throw new RuntimeException("verify-modeA-chain failed");
        return sizes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, intm.getEncoded().length, pemSize(staging.resolve("cv_int_certificate.pem").toString()), leaf.getEncoded().length, pemSize(staging.resolve("cv_leaf_certificate.pem").toString()), 0, 0);
    }

    private static long[] doVerifyModeBStrict(Path staging) throws Exception {
        X509Certificate leaf = ViewCommand.loadCertificate(staging.resolve("cv_leaf_certificate.pem").toString());
        X509Certificate intm = ViewCommand.loadCertificate(staging.resolve("cv_int_certificate.pem").toString());
        X509Certificate root = ViewCommand.loadCertificate(staging.resolve("cv_root_certificate.pem").toString());
        int rc = VerifyCommand.verifyModeB(leaf, intm, root, quiet);
        if (rc != 0) throw new RuntimeException("verify-modeB-strict failed");
        return chainSizes(staging, "cv_leaf_certificate.pem", "cv_int_certificate.pem", "cv_root_certificate.pem",
                leaf, intm, root);
    }

    private static long[] doVerifyDynamic(Path staging) throws Exception {
        X509Certificate leaf = ViewCommand.loadCertificate(staging.resolve("cv_leaf_certificate.pem").toString());
        X509Certificate intm = ViewCommand.loadCertificate(staging.resolve("cv_int_certificate.pem").toString());
        X509Certificate root = ViewCommand.loadCertificate(staging.resolve("cv_root_certificate.pem").toString());
        List<X509Certificate> untrusted = new ArrayList<>(); untrusted.add(intm);
        List<X509Certificate> trusted   = new ArrayList<>(); trusted.add(root);
        int rc = VerifyCommand.verifyDynamic(leaf, untrusted, trusted, quiet);
        if (rc != 0) throw new RuntimeException("verify-dynamic failed");
        return chainSizes(staging, "cv_leaf_certificate.pem", "cv_int_certificate.pem", "cv_root_certificate.pem",
                leaf, intm, root);
    }

    private static long[] doVerifyModeBDirect(Path staging) throws Exception {
        X509Certificate leaf = ViewCommand.loadCertificate(staging.resolve("direct_leaf_certificate.pem").toString());
        X509Certificate root = ViewCommand.loadCertificate(staging.resolve("direct_root_certificate.pem").toString());
        List<X509Certificate> trusted = new ArrayList<>(); trusted.add(root);
        int rc = VerifyCommand.verifyDynamic(leaf, new ArrayList<>(), trusted, quiet);
        if (rc != 0) throw new RuntimeException("verify-modeB-direct failed");
        long leafPem = pemSize(staging.resolve("direct_leaf_certificate.pem").toString());
        long rootPem = pemSize(staging.resolve("direct_root_certificate.pem").toString());
        return sizes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                leafPem, leaf.getEncoded().length, rootPem + leafPem, root.getEncoded().length + leaf.getEncoded().length);
    }

    // ── workflow-2tier ────────────────────────────────────────────────────────
    // Steps: cert → csr → sign (leaf) → verify (modeA leaf vs CA)

    private static long[] doWorkflow2tier(AlgorithmSet algorithmSet, String algoTag,
            Path staging, Path out) throws Exception {
        String pfx = out.resolve("wf2").toString();

        // Step 1: cert (CA)
        KeyPair caKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair caAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate caCert = CertificateGenerator.generateCertificate(
                algorithmSet, caKp, caAltKp, "CN=WF2CA-" + algoTag, 365.0);
        KeyGenerator.saveKeyToFile(pfx + "_ca_private_key.pem", caKp.getPrivate());
        KeyGenerator.saveKeyToFile(pfx + "_ca_public_key.pem", caKp.getPublic());
        if (caAltKp != null) {
            KeyGenerator.saveKeyToFile(pfx + "_ca_alt_private_key.pem", caAltKp.getPrivate());
            KeyGenerator.saveKeyToFile(pfx + "_ca_alt_public_key.pem", caAltKp.getPublic());
        }
        CertificateGenerator.saveCertificateToFile(pfx + "_ca_certificate.pem", caCert);

        // Step 2: csr (EE)
        KeyPair eeKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair eeAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X500Name eeSubject = new X500Name("CN=WF2EE-" + algoTag);
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(eeSubject, eeKp.getPublic());
        PKCS10CertificationRequest eeCsr;
        if (algorithmSet.isHybrid() && eeAltKp != null) {
            ContentSigner primary = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), eeKp);
            ContentSigner alt = CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), eeAltKp);
            eeCsr = builder.build(primary, eeAltKp.getPublic(), alt);
        } else {
            ContentSigner signer = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), eeKp);
            eeCsr = builder.build(signer);
        }
        CSRCommand.saveCsrToFile(pfx + "_ee_csr.pem", eeCsr);

        // Step 3: sign (leaf)
        PrivateKey caAltKey = (algorithmSet.isHybrid() && caAltKp != null) ? caAltKp.getPrivate() : null;
        X509Certificate leafCert = SignCommand.signCsr(eeCsr, caCert, caKp.getPrivate(), caAltKey,
                CertificateProfile.LEAF, 365);
        CertificateGenerator.saveCertificateToFile(pfx + "_leaf_certificate.pem", leafCert);

        // Step 4: verify (modeA: leaf vs CA)
        int rc = VerifyCommand.verifyModeA(leafCert, caCert, quiet);
        if (rc != 0) throw new RuntimeException("workflow-2tier verify step failed");

        long caCertPem = pemSize(pfx + "_ca_certificate.pem"), caCertDer = caCert.getEncoded().length;
        long leafPem = pemSize(pfx + "_leaf_certificate.pem"), leafDer = leafCert.getEncoded().length;
        return sizes(0, 0, 0, 0, 0, 0, 0, 0,
                caCertPem, caCertDer, 0, 0, 0, 0,
                leafPem, leafDer,
                caCertPem + leafPem, caCertDer + leafDer);
    }

    // ── workflow-3tier ────────────────────────────────────────────────────────
    // Steps: cert (root) → csr_int → sign_int (CA) → csr_leaf → sign_leaf → verify (modeB-strict)

    private static long[] doWorkflow3tier(AlgorithmSet algorithmSet, String algoTag,
            Path staging, Path out) throws Exception {
        String pfx = out.resolve("wf3").toString();

        // Step 1: cert (root)
        KeyPair rootKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair rootAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate rootCert = CertificateGenerator.generateCertificate(
                algorithmSet, rootKp, rootAltKp, "CN=WF3Root-" + algoTag, 365.0);
        KeyGenerator.saveKeyToFile(pfx + "_root_private_key.pem", rootKp.getPrivate());
        if (rootAltKp != null) KeyGenerator.saveKeyToFile(pfx + "_root_alt_private_key.pem", rootAltKp.getPrivate());
        CertificateGenerator.saveCertificateToFile(pfx + "_root_certificate.pem", rootCert);

        // Step 2: csr_int
        KeyPair intKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair intAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        JcaPKCS10CertificationRequestBuilder intBuilder =
                new JcaPKCS10CertificationRequestBuilder(
                        new X500Name("CN=WF3Int-" + algoTag), intKp.getPublic());
        PKCS10CertificationRequest intCsr;
        if (algorithmSet.isHybrid() && intAltKp != null) {
            ContentSigner ps = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), intKp);
            ContentSigner as = CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), intAltKp);
            intCsr = intBuilder.build(ps, intAltKp.getPublic(), as);
        } else {
            intCsr = intBuilder.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), intKp));
        }
        KeyGenerator.saveKeyToFile(pfx + "_int_private_key.pem", intKp.getPrivate());
        if (intAltKp != null) KeyGenerator.saveKeyToFile(pfx + "_int_alt_private_key.pem", intAltKp.getPrivate());

        // Step 3: sign_int (intermediate-ca)
        PrivateKey rootAltKey = (algorithmSet.isHybrid() && rootAltKp != null) ? rootAltKp.getPrivate() : null;
        X509Certificate intCert = SignCommand.signCsr(intCsr, rootCert, rootKp.getPrivate(), rootAltKey,
                CertificateProfile.INTERMEDIATE_CA, 365);
        CertificateGenerator.saveCertificateToFile(pfx + "_int_certificate.pem", intCert);

        // Step 4: csr_leaf
        KeyPair leafKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair leafAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        JcaPKCS10CertificationRequestBuilder leafBuilder =
                new JcaPKCS10CertificationRequestBuilder(
                        new X500Name("CN=WF3Leaf-" + algoTag), leafKp.getPublic());
        PKCS10CertificationRequest leafCsr;
        if (algorithmSet.isHybrid() && leafAltKp != null) {
            ContentSigner ps = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp);
            ContentSigner as = CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), leafAltKp);
            leafCsr = leafBuilder.build(ps, leafAltKp.getPublic(), as);
        } else {
            leafCsr = leafBuilder.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp));
        }

        // Step 5: sign_leaf
        PrivateKey intAltKey = (algorithmSet.isHybrid() && intAltKp != null) ? intAltKp.getPrivate() : null;
        X509Certificate leafCert = SignCommand.signCsr(leafCsr, intCert, intKp.getPrivate(), intAltKey,
                CertificateProfile.LEAF, 365);
        CertificateGenerator.saveCertificateToFile(pfx + "_leaf_certificate.pem", leafCert);

        // Step 6: verify (modeB-strict: leaf ← int ← root)
        int rc = VerifyCommand.verifyModeB(leafCert, intCert, rootCert, quiet);
        if (rc != 0) throw new RuntimeException("workflow-3tier verify step failed");

        long rootPem = pemSize(pfx + "_root_certificate.pem"), rootDer = rootCert.getEncoded().length;
        long intPem = pemSize(pfx + "_int_certificate.pem"), intDer = intCert.getEncoded().length;
        long leafPem = pemSize(pfx + "_leaf_certificate.pem"), leafDer = leafCert.getEncoded().length;
        return sizes(0, 0, 0, 0, 0, 0, 0, 0,
                rootPem, rootDer, 0, 0,
                intPem, intDer,
                leafPem, leafDer,
                rootPem + intPem + leafPem, rootDer + intDer + leafDer);
    }

    // ── Pre-generation ────────────────────────────────────────────────────────

    private static boolean pregen(AlgorithmSet algorithmSet, String algo, String algoTag,
            String op, Path staging) {
        try {
            switch (op) {
                case "keygen":
                case "cert":
                case "csr":
                case "workflow-2tier":
                case "workflow-3tier":
                    return true; // no pregen needed

                case "sign-leaf":
                    return pregenSignLeaf(algorithmSet, algoTag, staging);
                case "sign-intermediate-ca":
                    return pregenSignIntCA(algorithmSet, algoTag, staging);
                case "verify-selfsigned":
                    return pregenSelfSignedCert(algorithmSet, algoTag, staging);
                case "verify-issued":
                    return pregenVerifyIssued(algorithmSet, algoTag, staging);
                case "verify-modeA-chain":
                case "verify-modeB-strict":
                case "verify-dynamic":
                    return pregenChain(algorithmSet, algoTag, staging, "cv_");
                case "verify-modeB-direct":
                    return pregenDirectChain(algorithmSet, algoTag, staging);
                default:
                    System.err.println("[BENCH] Unknown op for pregen: " + op);
                    return false;
            }
        } catch (Exception e) {
            System.err.println("[BENCH] pregen exception for " + op + ": " + e.getMessage());
            return false;
        }
    }

    private static boolean pregenSignLeaf(AlgorithmSet algorithmSet, String algoTag, Path staging) throws Exception {
        // CA cert + key
        KeyPair caKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair caAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate caCert = CertificateGenerator.generateCertificate(
                algorithmSet, caKp, caAltKp, "CN=SignCA-" + algoTag, 365.0);
        KeyGenerator.saveKeyToFile(staging.resolve("ca_private_key.pem").toString(), caKp.getPrivate());
        if (caAltKp != null) KeyGenerator.saveKeyToFile(staging.resolve("ca_alt_private_key.pem").toString(), caAltKp.getPrivate());
        CertificateGenerator.saveCertificateToFile(staging.resolve("ca_certificate.pem").toString(), caCert);
        // EE CSR
        return pregenEeCsr(algorithmSet, algoTag, staging, caCert);
    }

    private static boolean pregenSignIntCA(AlgorithmSet algorithmSet, String algoTag, Path staging) throws Exception {
        // Root cert + key (reuse same structure as sign-leaf CA)
        return pregenSignLeaf(algorithmSet, algoTag, staging);
    }

    private static boolean pregenEeCsr(AlgorithmSet algorithmSet, String algoTag, Path staging,
            X509Certificate caCert) throws Exception {
        KeyPair eeKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair eeAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X500Name subject = new X500Name("CN=EE-" + algoTag);
        JcaPKCS10CertificationRequestBuilder b =
                new JcaPKCS10CertificationRequestBuilder(subject, eeKp.getPublic());
        PKCS10CertificationRequest csr;
        if (algorithmSet.isHybrid() && eeAltKp != null) {
            ContentSigner ps = CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), eeKp);
            ContentSigner as = CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), eeAltKp);
            csr = b.build(ps, eeAltKp.getPublic(), as);
        } else {
            csr = b.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), eeKp));
        }
        CSRCommand.saveCsrToFile(staging.resolve("ee_csr.pem").toString(), csr);
        return true;
    }

    private static boolean pregenSelfSignedCert(AlgorithmSet algorithmSet, String algoTag, Path staging) throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair altKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate cert = CertificateGenerator.generateCertificate(
                algorithmSet, kp, altKp, "CN=SelfCert-" + algoTag, 365.0);
        CertificateGenerator.saveCertificateToFile(staging.resolve("cert_certificate.pem").toString(), cert);
        return true;
    }

    private static boolean pregenVerifyIssued(AlgorithmSet algorithmSet, String algoTag, Path staging) throws Exception {
        KeyPair caKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair caAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate caCert = CertificateGenerator.generateCertificate(
                algorithmSet, caKp, caAltKp, "CN=VCertCA-" + algoTag, 365.0);
        CertificateGenerator.saveCertificateToFile(staging.resolve("vcert_ca_certificate.pem").toString(), caCert);
        KeyGenerator.saveKeyToFile(staging.resolve("vcert_ca_private_key.pem").toString(), caKp.getPrivate());
        if (caAltKp != null) KeyGenerator.saveKeyToFile(staging.resolve("vcert_ca_alt_private_key.pem").toString(), caAltKp.getPrivate());

        KeyPair leafKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair leafAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X500Name leafSubj = new X500Name("CN=VLeaf-" + algoTag);
        JcaPKCS10CertificationRequestBuilder b = new JcaPKCS10CertificationRequestBuilder(leafSubj, leafKp.getPublic());
        PKCS10CertificationRequest leafCsr;
        if (algorithmSet.isHybrid() && leafAltKp != null) {
            leafCsr = b.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp),
                    leafAltKp.getPublic(), CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), leafAltKp));
        } else {
            leafCsr = b.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp));
        }
        PrivateKey caAltKey = (algorithmSet.isHybrid() && caAltKp != null) ? caAltKp.getPrivate() : null;
        X509Certificate leafCert = SignCommand.signCsr(leafCsr, caCert, caKp.getPrivate(), caAltKey,
                CertificateProfile.LEAF, 365);
        CertificateGenerator.saveCertificateToFile(staging.resolve("vcert_leaf_certificate.pem").toString(), leafCert);
        return true;
    }

    private static boolean pregenChain(AlgorithmSet algorithmSet, String algoTag, Path staging,
            String prefix) throws Exception {
        // Root
        KeyPair rootKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair rootAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate rootCert = CertificateGenerator.generateCertificate(
                algorithmSet, rootKp, rootAltKp, "CN=CVRoot-" + algoTag, 365.0);
        CertificateGenerator.saveCertificateToFile(staging.resolve(prefix + "root_certificate.pem").toString(), rootCert);
        KeyGenerator.saveKeyToFile(staging.resolve(prefix + "root_private_key.pem").toString(), rootKp.getPrivate());
        if (rootAltKp != null) KeyGenerator.saveKeyToFile(staging.resolve(prefix + "root_alt_private_key.pem").toString(), rootAltKp.getPrivate());

        // Int
        KeyPair intKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair intAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X500Name intSubj = new X500Name("CN=CVInt-" + algoTag);
        JcaPKCS10CertificationRequestBuilder intB = new JcaPKCS10CertificationRequestBuilder(intSubj, intKp.getPublic());
        PKCS10CertificationRequest intCsr;
        if (algorithmSet.isHybrid() && intAltKp != null) {
            intCsr = intB.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), intKp),
                    intAltKp.getPublic(), CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), intAltKp));
        } else {
            intCsr = intB.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), intKp));
        }
        PrivateKey rootAltKey = (algorithmSet.isHybrid() && rootAltKp != null) ? rootAltKp.getPrivate() : null;
        X509Certificate intCert = SignCommand.signCsr(intCsr, rootCert, rootKp.getPrivate(), rootAltKey,
                CertificateProfile.INTERMEDIATE_CA, 365);
        CertificateGenerator.saveCertificateToFile(staging.resolve(prefix + "int_certificate.pem").toString(), intCert);
        KeyGenerator.saveKeyToFile(staging.resolve(prefix + "int_private_key.pem").toString(), intKp.getPrivate());
        if (intAltKp != null) KeyGenerator.saveKeyToFile(staging.resolve(prefix + "int_alt_private_key.pem").toString(), intAltKp.getPrivate());

        // Leaf
        KeyPair leafKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair leafAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X500Name leafSubj = new X500Name("CN=CVLeaf-" + algoTag);
        JcaPKCS10CertificationRequestBuilder leafB = new JcaPKCS10CertificationRequestBuilder(leafSubj, leafKp.getPublic());
        PKCS10CertificationRequest leafCsr;
        if (algorithmSet.isHybrid() && leafAltKp != null) {
            leafCsr = leafB.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp),
                    leafAltKp.getPublic(), CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), leafAltKp));
        } else {
            leafCsr = leafB.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp));
        }
        PrivateKey intAltKey = (algorithmSet.isHybrid() && intAltKp != null) ? intAltKp.getPrivate() : null;
        X509Certificate leafCert = SignCommand.signCsr(leafCsr, intCert, intKp.getPrivate(), intAltKey,
                CertificateProfile.LEAF, 365);
        CertificateGenerator.saveCertificateToFile(staging.resolve(prefix + "leaf_certificate.pem").toString(), leafCert);
        return true;
    }

    private static boolean pregenDirectChain(AlgorithmSet algorithmSet, String algoTag, Path staging) throws Exception {
        // Root issues leaf directly (no intermediate)
        KeyPair rootKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair rootAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X509Certificate rootCert = CertificateGenerator.generateCertificate(
                algorithmSet, rootKp, rootAltKp, "CN=DRoot-" + algoTag, 365.0);
        CertificateGenerator.saveCertificateToFile(staging.resolve("direct_root_certificate.pem").toString(), rootCert);
        KeyGenerator.saveKeyToFile(staging.resolve("direct_root_private_key.pem").toString(), rootKp.getPrivate());
        if (rootAltKp != null) KeyGenerator.saveKeyToFile(staging.resolve("direct_root_alt_private_key.pem").toString(), rootAltKp.getPrivate());

        KeyPair leafKp = KeyGenerator.generateKeyPair(algorithmSet.getAlgorithms());
        KeyPair leafAltKp = algorithmSet.isHybrid() ? KeyGenerator.generateKeyPair(algorithmSet.getAltAlgorithms()) : null;
        X500Name leafSubj = new X500Name("CN=DLeaf-" + algoTag);
        JcaPKCS10CertificationRequestBuilder b = new JcaPKCS10CertificationRequestBuilder(leafSubj, leafKp.getPublic());
        PKCS10CertificationRequest leafCsr;
        if (algorithmSet.isHybrid() && leafAltKp != null) {
            leafCsr = b.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp),
                    leafAltKp.getPublic(), CertificateGenerator.getSigner(algorithmSet.getAltAlgorithms(), leafAltKp));
        } else {
            leafCsr = b.build(CertificateGenerator.getSigner(algorithmSet.getAlgorithms(), leafKp));
        }
        PrivateKey rootAltKey = (algorithmSet.isHybrid() && rootAltKp != null) ? rootAltKp.getPrivate() : null;
        X509Certificate leafCert = SignCommand.signCsr(leafCsr, rootCert, rootKp.getPrivate(), rootAltKey,
                CertificateProfile.LEAF, 365);
        CertificateGenerator.saveCertificateToFile(staging.resolve("direct_leaf_certificate.pem").toString(), leafCert);
        return true;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static void writeSizes(Path path, long[] s) throws IOException {
        StringBuilder sb = new StringBuilder(SIZES_HEADER);
        for (int i = 0; i < s.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(s[i]);
        }
        sb.append('\n');
        Files.writeString(path, sb.toString());
    }

    private static long[] sizes(long... vals) { return vals; }

    private static long[] chainSizes(Path staging, String leafFile, String intFile, String rootFile,
            X509Certificate leaf, X509Certificate intm, X509Certificate root) throws Exception {
        long leafPem = pemSize(staging.resolve(leafFile).toString());
        long intPem  = pemSize(staging.resolve(intFile).toString());
        long rootPem = pemSize(staging.resolve(rootFile).toString());
        long leafDer = leaf.getEncoded().length, intDer = intm.getEncoded().length, rootDer = root.getEncoded().length;
        return sizes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                intPem, intDer, leafPem, leafDer,
                rootPem + intPem + leafPem, rootDer + intDer + leafDer);
    }

    private static long pemSize(String path) {
        File f = new File(path);
        return f.exists() ? f.length() : 0;
    }

    private static String execModel(String op) {
        return (op.startsWith("workflow-")) ? "direct-core-workflow" : "direct-core";
    }

    private static String escapeCsv(String s) {
        if (s == null || s.isEmpty()) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    private static class IterResult {
        final long elapsedNs;
        final boolean success;
        final String error;
        final long[] sizes;
        IterResult(long ns, boolean ok, String err, long[] sz) {
            elapsedNs = ns; success = ok; error = err; sizes = sz;
        }
    }
}
