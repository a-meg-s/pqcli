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
