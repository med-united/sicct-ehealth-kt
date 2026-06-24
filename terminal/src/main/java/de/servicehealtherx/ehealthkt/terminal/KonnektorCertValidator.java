package de.servicehealtherx.ehealthkt.terminal;

import java.security.cert.Certificate;

/**
 * Validates the Konnektor's TLS client certificate chain. The default implementation accepts any
 * peer certificate (suitable for the {@code sim} mode and tests). A production implementation can
 * verify the chain and role against the gematik TSL using {@code gemLibPki}.
 */
@FunctionalInterface
public interface KonnektorCertValidator {

    boolean isAcceptable(Certificate[] chain);

    /** Accept any presented client certificate. */
    static KonnektorCertValidator acceptAll() {
        return chain -> chain != null && chain.length > 0;
    }
}
