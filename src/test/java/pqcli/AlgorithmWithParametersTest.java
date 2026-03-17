package pqcli;

import org.junit.Test;
import static org.junit.Assert.*;

public class AlgorithmWithParametersTest {

    // --- Normalization ---

    @Test
    public void rsaUpperCaseNormalized() {
        AlgorithmWithParameters a = new AlgorithmWithParameters("RSA:3072");
        assertEquals("rsa", a.algorithm);
        assertEquals("3072", a.keySizeOrCurve);
    }

    @Test
    public void mlDsaAliasesAllResolveToMldsa() {
        assertEquals("mldsa", new AlgorithmWithParameters("ML-DSA:65").algorithm);
        assertEquals("mldsa", new AlgorithmWithParameters("MLDSA:65").algorithm);
        assertEquals("mldsa", new AlgorithmWithParameters("Dilithium:65").algorithm);
    }

    @Test
    public void mlDsaLevelAliases() {
        assertEquals("44", new AlgorithmWithParameters("ML-DSA:2").keySizeOrCurve);
        assertEquals("65", new AlgorithmWithParameters("ML-DSA:3").keySizeOrCurve);
        assertEquals("87", new AlgorithmWithParameters("ML-DSA:5").keySizeOrCurve);
        assertEquals("44", new AlgorithmWithParameters("ML-DSA:44").keySizeOrCurve);
        assertEquals("65", new AlgorithmWithParameters("ML-DSA:65").keySizeOrCurve);
        assertEquals("87", new AlgorithmWithParameters("ML-DSA:87").keySizeOrCurve);
    }

    @Test
    public void slhDsaAliases() {
        assertEquals("slh-dsa", new AlgorithmWithParameters("SLH-DSA:128s").algorithm);
        assertEquals("slh-dsa", new AlgorithmWithParameters("SPHINCS+:128s").algorithm);
        assertEquals("slh-dsa", new AlgorithmWithParameters("sphincsplus:128s").algorithm);
    }

    @Test
    public void ecCurveAliases() {
        assertEquals("secp256r1", new AlgorithmWithParameters("EC:P-256").keySizeOrCurve);
        assertEquals("secp256r1", new AlgorithmWithParameters("EC:p256").keySizeOrCurve);
        assertEquals("secp256r1", new AlgorithmWithParameters("EC:nistp256").keySizeOrCurve);
        assertEquals("secp256r1", new AlgorithmWithParameters("EC:prime256v1").keySizeOrCurve);
        assertEquals("secp384r1", new AlgorithmWithParameters("EC:P-384").keySizeOrCurve);
        assertEquals("secp521r1", new AlgorithmWithParameters("EC:P-521").keySizeOrCurve);
    }

    // --- Default parameters ---

    @Test
    public void rsaDefaultKeySize() {
        AlgorithmWithParameters a = new AlgorithmWithParameters("RSA");
        assertEquals("3072", a.keySizeOrCurve);
    }

    @Test
    public void mlDsaDefaultLevel() {
        AlgorithmWithParameters a = new AlgorithmWithParameters("ML-DSA");
        assertEquals("65", a.keySizeOrCurve);
    }

    @Test
    public void ecDefaultCurve() {
        AlgorithmWithParameters a = new AlgorithmWithParameters("EC");
        assertEquals("secp256r1", a.keySizeOrCurve);
    }

    @Test
    public void ed25519NoParams() {
        AlgorithmWithParameters a = new AlgorithmWithParameters("Ed25519");
        assertEquals("ed25519", a.algorithm);
        assertEquals("", a.keySizeOrCurve);
    }

    // --- toString ---

    @Test
    public void toStringWithParams() {
        assertEquals("rsa:3072", new AlgorithmWithParameters("RSA:3072").toString());
    }

    @Test
    public void toStringNoParams() {
        assertEquals("ed25519", new AlgorithmWithParameters("Ed25519").toString());
    }

    // --- Error cases ---

    @Test(expected = IllegalArgumentException.class)
    public void tooManyColonsThrows() {
        new AlgorithmWithParameters("RSA:3072:extra");
    }
}
