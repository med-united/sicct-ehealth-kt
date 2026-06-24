package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jce.ECNamedCurveTable;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Conversions between the plain {@code r||s} ECDSA signature format used by the gSMC-KT
 * (and on the SICCT wire) and the DER encoding expected by the JCA verifier.
 * The curve is brainpoolP256r1, hence a 32-byte field size.
 */
public final class EcdsaSignatures {

    public static final String CURVE = "brainpoolP256r1";
    private static final int FIELD_SIZE = 32;

    private EcdsaSignatures() {
    }

    /** Convert a plain {@code r||s} signature (64 bytes) to DER. */
    public static byte[] plainToDer(byte[] plain) {
        BigInteger r = new BigInteger(1, plain, 0, FIELD_SIZE);
        BigInteger s = new BigInteger(1, plain, FIELD_SIZE, FIELD_SIZE);
        try {
            BigInteger n = ECNamedCurveTable.getParameterSpec(CURVE).getN();
            return StandardDSAEncoding.INSTANCE.encode(n, r, s);
        } catch (IOException e) {
            throw new IllegalStateException("Could not DER-encode ECDSA signature", e);
        }
    }

    /** Convert a DER ECDSA signature to plain {@code r||s} (64 bytes). */
    public static byte[] derToPlain(byte[] der) {
        try {
            BigInteger n = ECNamedCurveTable.getParameterSpec(CURVE).getN();
            BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(n, der);
            byte[] out = new byte[FIELD_SIZE * 2];
            copyFixed(rs[0], out, 0);
            copyFixed(rs[1], out, FIELD_SIZE);
            return out;
        } catch (IOException e) {
            throw new IllegalStateException("Could not decode DER ECDSA signature", e);
        }
    }

    private static void copyFixed(BigInteger v, byte[] out, int offset) {
        byte[] b = v.toByteArray();
        // strip a possible leading sign byte, or left-pad to FIELD_SIZE
        if (b.length > FIELD_SIZE) {
            b = Arrays.copyOfRange(b, b.length - FIELD_SIZE, b.length);
        }
        System.arraycopy(b, 0, out, offset + (FIELD_SIZE - b.length), b.length);
    }
}
