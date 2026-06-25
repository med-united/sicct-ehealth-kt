package de.servicehealtherx.ehealthkt.gsmckt;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * The cryptographic identity of the eHealth-KT, anchored in the gSMC-KT (SM-KT).
 * Provides the SM-KT authentication certificate and produces the pairing signature
 * used during EHEALTH TERMINAL AUTHENTICATE (CREATE).
 *
 * <p>Two implementations exist: {@link SoftwareTerminalIdentity} (in-memory, for
 * hardware-free testing) and {@link GsmcKtCardIdentity} (a real gSMC-KT over PC/SC).
 */
public interface TerminalIdentity extends AutoCloseable {

    /** The SM-KT authentication certificate (C.SMKT.AUT). */
    X509Certificate getCertificate();

    /** Public key of the SM-KT (from the certificate). */
    PublicKey getPublicKey();

    /** Whether the SM-KT key is RSA or EC. */
    KeyType getKeyType();

    /**
     * Produce the pairing signature over the Konnektor-supplied shared secret, as expected
     * by EHEALTH TERMINAL AUTHENTICATE (CREATE):
     * <ul>
     *   <li>RSA: RSASSA-PSS (SHA-256) over the shared secret — 256 bytes.</li>
     *   <li>EC: ECDSA over SHA-256(shared secret), returned as plain {@code r||s} — 64 bytes.</li>
     * </ul>
     */
    byte[] signPairingSecret(byte[] sharedSecret);

    /**
     * Generate {@code length} random bytes using the SM-KT random number generator, as required for
     * the challenge of EHEALTH TERMINAL AUTHENTICATE (ADD Phase 1, gemSpec_KT SEQ_KT_0003 step 1).
     * The default uses a JCA {@link java.security.SecureRandom}; a real gSMC-KT overrides this to
     * draw from the card's RNG (GET CHALLENGE).
     */
    default byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        new java.security.SecureRandom().nextBytes(out);
        return out;
    }

    @Override
    default void close() {
    }
}
