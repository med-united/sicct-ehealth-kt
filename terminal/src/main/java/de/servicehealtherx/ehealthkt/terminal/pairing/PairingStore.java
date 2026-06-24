package de.servicehealtherx.ehealthkt.terminal.pairing;

import java.util.Optional;

/**
 * Persistence of {@link PairingBlock}s. Implementations may keep them in memory, in a JSON file
 * ({@link FilePairingStore}) or in a TPM-protected store (future).
 */
public interface PairingStore {

    /** Add a new pairing block (CREATE phase). */
    void add(PairingBlock block);

    /** Find the pairing block bound to the given Konnektor public key, if any. */
    Optional<PairingBlock> findByPublicKey(String publicKeyHex);

    /** Whether any pairing exists for the given public key. */
    default boolean isPaired(String publicKeyHex) {
        return findByPublicKey(publicKeyHex).isPresent();
    }

    /** Persist the current state (no-op for in-memory stores). */
    default void flush() {
    }
}
