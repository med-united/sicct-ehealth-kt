package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Conversions between the plain {@code r||s} ECDSA signature format used by the gSMC-KT
 * (and on the SICCT wire) and the DER encoding expected by the JCA verifier.
 *
 * <p>The gSMC-KT curve (brainpoolP256r1 on real hardware, secp256r1 for the software stand-in)
 * has a 256-bit field, hence a 32-byte {@code r} and {@code s}. The conversion is purely a
 * re-encoding of the two integers and deliberately does not validate them against a particular
 * curve order, so it is not tied to one curve and works for any 256-bit ECDSA signature.
 */
public final class EcdsaSignatures {

    public static final String CURVE = "brainpoolP256r1";
    private static final int FIELD_SIZE = 32;

    private EcdsaSignatures() {
    }

    /** Convert a plain {@code r||s} signature (64 bytes) to DER {@code SEQUENCE { INTEGER r, INTEGER s }}. */
    public static byte[] plainToDer(byte[] plain) {
        BigInteger r = new BigInteger(1, plain, 0, FIELD_SIZE);
        BigInteger s = new BigInteger(1, plain, FIELD_SIZE, FIELD_SIZE);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Could not DER-encode ECDSA signature", e);
        }
    }

    /** Convert a DER ECDSA signature to plain {@code r||s} (64 bytes). */
    public static byte[] derToPlain(byte[] der) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue();
        byte[] out = new byte[FIELD_SIZE * 2];
        copyFixed(r, out, 0);
        copyFixed(s, out, FIELD_SIZE);
        return out;
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
