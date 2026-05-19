package pqcli.bench;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import pqcli.KeyGenerator;

import java.security.*;
import java.util.concurrent.TimeUnit;

/**
 * Layer A — primitive cryptographic operations (no CLI, no file I/O).
 *
 * Benchmarks:
 *   keygen  — raw KeyPair generation via BC
 *   sign    — Signature.sign() on a fixed message with a pre-generated key
 *   verify  — Signature.verify() on a pre-computed signature
 *
 * Algorithms: RSA-3072, ECDSA-P256, Ed25519, ML-DSA-65
 * (Hybrid and composite are PKI-level constructs — see LayerBBenchmark)
 *
 * JMH defaults (overridable via CLI args to run_micro.sh):
 *   mode:        AverageTime
 *   time unit:   ms (milliseconds)
 *   warmup:      10 iterations × 1s
 *   measurement: 20 iterations × 1s  (5 forks × 20 = 100 total measured)
 *   forks:       5
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 20, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(value = 5, jvmArgsAppend = {"-Xms512m", "-Xmx512m", "-XX:+UseG1GC"})
public class LayerABenchmark {

    /**
     * Short algorithm tags — avoids comma/colon ambiguity in JMH @Param and CLI.
     * Maps to pqcli KeyGenerator.generateKeyPair(String algorithm, String params).
     */
    @Param({"rsa3072", "ecdsa-p256", "ed25519", "mldsa65"})
    public String algoTag;

    // Fields set in @Setup — reused across iterations within each fork
    private String bcAlgoName;    // BC KeyPairGenerator algorithm name
    private String bcAlgoParams;  // BC key size / curve
    private String jcaSigAlgo;    // JCA Signature algorithm name

    private KeyPair keyPair;
    private byte[] message;
    private byte[] precomputedSignature;

    @Setup(Level.Trial)
    public void setupTrial() throws Exception {
        // Register BC providers if not already present (safe to call multiple times)
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        // Map tag → (KeyGenerator args, JCA sig algorithm)
        switch (algoTag) {
            case "rsa3072":
                bcAlgoName = "rsa"; bcAlgoParams = "3072"; jcaSigAlgo = "SHA384withRSA";
                break;
            case "ecdsa-p256":
                bcAlgoName = "ec";  bcAlgoParams = "secp256r1"; jcaSigAlgo = "SHA256withECDSA";
                break;
            case "ed25519":
                bcAlgoName = "ed25519"; bcAlgoParams = ""; jcaSigAlgo = "Ed25519";
                break;
            case "mldsa65":
                bcAlgoName = "mldsa"; bcAlgoParams = "65"; jcaSigAlgo = "ML-DSA-65";
                break;
            default:
                throw new IllegalArgumentException("Unknown algoTag: " + algoTag);
        }

        // Pre-generate key pair (key generation is benchmarked separately in keygen())
        keyPair = KeyGenerator.generateKeyPair(bcAlgoName, bcAlgoParams);

        // Fixed message for sign/verify — same across all iterations
        message = "pqcli benchmark: layer A sign/verify test message".getBytes();

        // Pre-compute signature for the verify benchmark
        Signature signer = Signature.getInstance(jcaSigAlgo, "BC");
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        precomputedSignature = signer.sign();
    }

    /**
     * Layer A — keygen.
     * Times KeyPairGenerator.generateKeyPair() only.
     * JVM startup, provider init, and key pre-generation are excluded (done in @Setup).
     */
    @Benchmark
    public KeyPair keygen(Blackhole bh) throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(bcAlgoName, bcAlgoParams);
        bh.consume(kp);
        return kp;
    }

    /**
     * Layer A — sign.
     * Times Signature.getInstance() + initSign() + update() + sign() for a fixed message.
     * A new Signature instance is created each iteration to avoid state reuse artifacts.
     */
    @Benchmark
    public byte[] sign(Blackhole bh) throws Exception {
        Signature sig = Signature.getInstance(jcaSigAlgo, "BC");
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        byte[] s = sig.sign();
        bh.consume(s);
        return s;
    }

    /**
     * Layer A — verify.
     * Times Signature.getInstance() + initVerify() + update() + verify() for a pre-computed signature.
     * The signature value is the same across all iterations (pre-computed in @Setup).
     */
    @Benchmark
    public boolean verify(Blackhole bh) throws Exception {
        Signature sig = Signature.getInstance(jcaSigAlgo, "BC");
        sig.initVerify(keyPair.getPublic());
        sig.update(message);
        boolean result = sig.verify(precomputedSignature);
        bh.consume(result);
        return result;
    }
}
