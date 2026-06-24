package de.servicehealtherx.ehealthkt.terminal;

/**
 * Connection state of a SICCT/TLS session, per gemSpec_KT. Determines which commands are allowed.
 */
public enum SicctState {
    /** TLS handshake not yet complete. */
    NO_SICCT_TLS,
    /** Handshake complete but client certificate missing/untrusted. */
    INVALID_CLIENT,
    /** Valid client, but no pairing yet: only session/status/authenticate-create allowed. */
    CLIENT_WITHOUT_PAIRING,
    /** Valid client with an established pairing: full command set allowed. */
    CLIENT_WITH_PAIRING
}
