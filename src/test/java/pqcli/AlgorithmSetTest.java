package pqcli;

import org.junit.Test;
import static org.junit.Assert.*;

public class AlgorithmSetTest {

    // --- Single algorithm ---

    @Test
    public void singleAlgorithm() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072");
        assertFalse(s.isComposite());
        assertFalse(s.isHybrid());
        assertEquals(1, s.getAlgorithms().length);
        assertEquals("rsa", s.getAlgorithm().algorithm);
        assertEquals("3072", s.getAlgorithm().keySizeOrCurve);
    }

    // --- Hybrid (comma-separated) ---

    @Test
    public void hybridTwoAlgorithms() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072,ML-DSA:65");
        assertFalse(s.isComposite());
        assertTrue(s.isHybrid());
        assertEquals("rsa",   s.getAlgorithm().algorithm);
        assertEquals("mldsa", s.getAltAlgorithm().algorithm);
        assertEquals("65",    s.getAltAlgorithm().keySizeOrCurve);
    }

    @Test(expected = IllegalArgumentException.class)
    public void hybridMoreThanTwoThrows() {
        new AlgorithmSet("RSA:3072,ML-DSA:65,SLH-DSA:128s");
    }

    // --- Composite (underscore-separated) ---

    @Test
    public void compositeTwoAlgorithms() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072_ML-DSA:65");
        assertTrue(s.isComposite());
        assertFalse(s.isHybrid());
        assertEquals(2, s.getAlgorithms().length);
        assertEquals("rsa",   s.getAlgorithm(0).algorithm);
        assertEquals("mldsa", s.getAlgorithm(1).algorithm);
    }

    @Test
    public void compositeThreeAlgorithms() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072_ML-DSA:65_SLH-DSA:128s");
        assertTrue(s.isComposite());
        assertEquals(3, s.getAlgorithms().length);
    }

    // --- Hybrid composite alt ---

    @Test
    public void hybridWhereAltIsComposite() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072,ML-DSA:65_SLH-DSA:128s");
        assertTrue(s.isHybrid());
        assertFalse(s.isComposite());
        assertTrue(s.isAltComposite());
        assertEquals(2, s.getAltAlgorithms().length);
    }

    // --- resolveNamedComposite ---

    @Test
    public void resolveNamedCompositeRsaMlDsa65() {
        AlgorithmWithParameters[] algos = new AlgorithmSet("RSA:3072_ML-DSA:65").getAlgorithms();
        assertEquals("MLDSA65-RSA3072-PSS-SHA512", AlgorithmSet.resolveNamedComposite(algos));
    }

    @Test
    public void resolveNamedCompositeOrderIndependent() {
        // ML-DSA first
        AlgorithmWithParameters[] a = new AlgorithmSet("ML-DSA:65_RSA:3072").getAlgorithms();
        // RSA first
        AlgorithmWithParameters[] b = new AlgorithmSet("RSA:3072_ML-DSA:65").getAlgorithms();
        assertEquals(AlgorithmSet.resolveNamedComposite(a), AlgorithmSet.resolveNamedComposite(b));
    }

    @Test
    public void resolveNamedCompositeStripsPssSuffix() {
        // RSA:3072-pss should resolve the same as RSA:3072 (PSS is always used for composite RSA)
        AlgorithmWithParameters[] a = new AlgorithmSet("RSA:3072-pss_ML-DSA:65").getAlgorithms();
        AlgorithmWithParameters[] b = new AlgorithmSet("RSA:3072_ML-DSA:65").getAlgorithms();
        assertEquals(AlgorithmSet.resolveNamedComposite(b), AlgorithmSet.resolveNamedComposite(a));
    }

    @Test
    public void resolveNamedCompositeWithDefaultMlDsaParam() {
        // ML-DSA without explicit level defaults to 65
        AlgorithmWithParameters[] algos = new AlgorithmSet("ML-DSA_RSA:3072").getAlgorithms();
        assertEquals("MLDSA65-RSA3072-PSS-SHA512", AlgorithmSet.resolveNamedComposite(algos));
    }

    @Test
    public void resolveNamedCompositeEcVariants() {
        assertEquals("MLDSA65-ECDSA-P256-SHA512",
            AlgorithmSet.resolveNamedComposite(new AlgorithmSet("EC:secp256r1_ML-DSA:65").getAlgorithms()));
        assertEquals("MLDSA65-ECDSA-P384-SHA512",
            AlgorithmSet.resolveNamedComposite(new AlgorithmSet("EC:P-384_ML-DSA:65").getAlgorithms()));
        assertEquals("MLDSA87-Ed448-SHAKE256",
            AlgorithmSet.resolveNamedComposite(new AlgorithmSet("Ed448_ML-DSA:87").getAlgorithms()));
    }

    @Test
    public void resolveNamedCompositeReturnsNullForUnsupported() {
        // SLH-DSA has no named draft combination
        assertNull(AlgorithmSet.resolveNamedComposite(new AlgorithmSet("SLH-DSA:128s_ML-DSA:65").getAlgorithms()));
        // 3-component composites not supported
        assertNull(AlgorithmSet.resolveNamedComposite(new AlgorithmSet("RSA:3072_ML-DSA:65_EC").getAlgorithms()));
        // Two non-ML-DSA components
        assertNull(AlgorithmSet.resolveNamedComposite(new AlgorithmSet("RSA:3072_EC").getAlgorithms()));
    }

    // --- Error cases ---

    @Test(expected = IllegalArgumentException.class)
    public void emptyStringThrows() {
        new AlgorithmSet("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void outOfBoundsIndexThrows() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072");
        s.getAlgorithm(1);
    }

    @Test(expected = IllegalStateException.class)
    public void getAltAlgorithmOnNonHybridThrows() {
        AlgorithmSet s = new AlgorithmSet("RSA:3072");
        s.getAltAlgorithm();
    }
}
