package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;

import java.security.MessageDigest;

/**
 * A {@link MessageDigest} that does not hash but simply returns the bytes fed to it. The TLS
 * provider (BCJSSE) pre-computes the handshake hash (or builds the PKCS#1 DigestInfo) before
 * calling the card-backed {@code Signature}; the gSMC-KT then performs the actual digital-signature
 * primitive over those bytes. Using a null digest lets the signature SPIs reuse the standard
 * {@code SignatureSpi} digest plumbing while leaving the hashing to the TLS layer / the card.
 */
public class NullMessageDigest extends MessageDigest {

    private Digest digest = new NullDigest();

    public NullMessageDigest() {
        super("NullMessageDigest");
    }

    @Override
    protected void engineUpdate(byte input) {
        digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        digest = new NullDigest();
    }
}
