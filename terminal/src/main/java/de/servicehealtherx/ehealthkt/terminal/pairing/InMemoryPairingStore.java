package de.servicehealtherx.ehealthkt.terminal.pairing;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A volatile pairing store. Useful for tests and stateless deployments.
 */
public class InMemoryPairingStore implements PairingStore {

    protected final List<PairingBlock> blocks = new CopyOnWriteArrayList<>();

    @Override
    public void add(PairingBlock block) {
        blocks.add(block);
    }

    @Override
    public Optional<PairingBlock> findByPublicKey(String publicKeyHex) {
        return blocks.stream().filter(b -> b.containsPublicKey(publicKeyHex)).findFirst();
    }
}
