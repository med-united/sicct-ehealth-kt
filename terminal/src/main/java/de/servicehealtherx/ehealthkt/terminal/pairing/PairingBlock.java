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
}
