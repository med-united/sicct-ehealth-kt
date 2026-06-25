package de.servicehealtherx.ehealthkt.gsmckt;

import java.security.KeyStore;

/**
 * A {@link KeyStore} built directly around an already-connected {@link GsmcKtCardIdentity}, without
 * going through a registered security {@code Provider} (which would open a second PC/SC connection).
 * Use {@link #of(GsmcKtCardIdentity)} to obtain a loaded, ready-to-use keystore for a
 * {@code KeyManagerFactory}.
 */
public final class GsmcKtKeyStore extends KeyStore {

    private GsmcKtKeyStore(GsmcKtKeyStoreSpi spi) {
        super(spi, null, "GSMCkt");
    }

    /** Build and initialise a keystore backed by the given card identity. */
    public static KeyStore of(GsmcKtCardIdentity card) {
        try {
            GsmcKtKeyStore keyStore = new GsmcKtKeyStore(new GsmcKtKeyStoreSpi(card));
            keyStore.load(null, null); // marks the KeyStore as initialised
            return keyStore;
        } catch (Exception e) {
            throw new IllegalStateException("Could not build gSMC-KT keystore", e);
        }
    }
}
