package de.servicehealtherx.ehealthkt.terminal.pairing;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A pairing between this terminal and a Konnektor: the shared secret the Konnektor supplied
 * during EHEALTH TERMINAL AUTHENTICATE (CREATE), together with the public key(s) of the
 * Konnektor TLS client certificate(s) it is bound to.
 *
 * <p>Per gemSpec_KT TIP1-A_3043 the shared secret is stored in the terminal (here), not on the
 * SM-KT. Values are kept hex-encoded for stable JSON serialization.
 */
public class PairingBlock {

    /**
     * Maximum number of public keys a pairing block holds. gemSpec_KT TIP1-A_3046-01 requires the
     * terminal to support a cardinality of up to 3 keys per block. The set keeps insertion order so
     * the "oldest" key (longest-ago pairing) can be evicted first when full (ADD Phase 2, step 7).
     */
    public static final int MAX_PUBLIC_KEYS = 3;

    private String sharedSecretHex;
    private Set<String> publicKeysHex = new LinkedHashSet<>();

    public PairingBlock() {
    }

    public PairingBlock(String sharedSecretHex) {
        this.sharedSecretHex = sharedSecretHex;
    }

    public String getSharedSecretHex() {
        return sharedSecretHex;
    }

    public void setSharedSecretHex(String sharedSecretHex) {
        this.sharedSecretHex = sharedSecretHex;
    }

    public Set<String> getPublicKeysHex() {
        return publicKeysHex;
    }

    public void setPublicKeysHex(Set<String> publicKeysHex) {
        this.publicKeysHex = publicKeysHex;
    }

    public void addPublicKey(String publicKeyHex) {
        publicKeysHex.add(publicKeyHex);
    }

    public boolean containsPublicKey(String publicKeyHex) {
        return publicKeysHex.contains(publicKeyHex);
    }

    public boolean removePublicKey(String publicKeyHex) {
        return publicKeysHex.remove(publicKeyHex);
    }

    /**
     * Bind a (new) Konnektor public key to this block following the EHEALTH TERMINAL AUTHENTICATE
     * ADD Phase 2 rules (gemSpec_KT SEQ_KT_0004, step 7):
     * <ul>
     *   <li>already present: no change;</li>
     *   <li>a free slot exists: append it;</li>
     *   <li>full ({@link #MAX_PUBLIC_KEYS}): overwrite the oldest key (longest-ago pairing).</li>
     * </ul>
     */
    public void bindPublicKey(String publicKeyHex) {
        if (publicKeysHex.contains(publicKeyHex)) {
            return;
        }
        if (publicKeysHex.size() >= MAX_PUBLIC_KEYS) {
            String oldest = publicKeysHex.iterator().next();
            publicKeysHex.remove(oldest);
        }
        publicKeysHex.add(publicKeyHex);
    }
}
