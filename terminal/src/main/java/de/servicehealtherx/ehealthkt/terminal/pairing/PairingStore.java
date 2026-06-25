package de.servicehealtherx.ehealthkt.terminal.pairing;

import java.util.List;
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

    /**
     * All stored pairing blocks. EHEALTH TERMINAL AUTHENTICATE (ADD Phase 2) iterates these to find
     * the block whose shared secret the Konnektor proved knowledge of.
     */
    List<PairingBlock> all();

    /**
     * Persist mutations made in place to a block returned by {@link #all()} or
     * {@link #findByPublicKey}. Equivalent to {@link #flush()}; named for intent at call sites.
     */
    default void update(PairingBlock block) {
        flush();
    }

    /** Whether any pairing exists for the given public key. */
    default boolean isPaired(String publicKeyHex) {
        return findByPublicKey(publicKeyHex).isPresent();
    }

    /** Persist the current state (no-op for in-memory stores). */
    default void flush() {
    }
}
