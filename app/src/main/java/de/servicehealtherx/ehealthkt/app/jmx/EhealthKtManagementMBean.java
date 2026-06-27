package de.servicehealtherx.ehealthkt.app.jmx;

/**
 * Standard JMX MBean for managing a running eHealth-KT. Exposes the four operator tasks that the
 * standalone terminal cannot perform itself in server mode:
 *
 * <ul>
 *   <li><b>Confirm pairing</b> — answer the EHEALTH TERMINAL AUTHENTICATE (CREATE) confirmation
 *       prompt that the Konnektor triggered ({@link #confirmPairing()} / {@link #rejectPairing()}).</li>
 *   <li><b>Enter a PIN</b> — supply the PIN for a host (remote) PERFORM VERIFICATION
 *       ({@link #enterPin(String)} / {@link #cancelPin()}).</li>
 *   <li><b>Connection state</b> — inspect the SICCT/TLS server and active paired sessions.</li>
 *   <li><b>gSMC-KT certificate</b> — read the SM-KT authentication certificate the terminal
 *       presents as its TLS identity.</li>
 * </ul>
 *
 * <p>Registered under the object name {@value #OBJECT_NAME}. Attach with {@code jconsole} or any
 * JMX client (enable remote access via the standard {@code -Dcom.sun.management.jmxremote.*} flags).
 */
public interface EhealthKtManagementMBean {

    String OBJECT_NAME = "de.servicehealtherx.ehealthkt:type=Management,name=eHealth-KT";

    // --- Connection state ---

    /** TCP port the SICCT TLS server is bound to. */
    int getPort();

    /** Number of active, paired SICCT/TLS sessions (connected Konnektoren). */
    int getActiveSessions();

    /** Number of pairing blocks stored on the terminal. */
    int getPairingBlocks();

    /** Total number of Konnektor public keys bound across all pairing blocks. */
    int getBoundKonnektorKeys();

    /** Human-readable one-line summary of the connection and pairing state. */
    String getConnectionState();

    // --- Pairing block management ---

    /** Human-readable, indexed listing of all stored pairing blocks (secrets masked). */
    String listPairingBlocks();

    /**
     * Remove the pairing block at the given (zero-based) index, as shown by
     * {@link #listPairingBlocks()}. Throws {@link IllegalArgumentException} if the index is invalid.
     */
    String removePairingBlock(int index);

    /**
     * Remove the pairing block bound to the given Konnektor public key (hex). Throws
     * {@link IllegalArgumentException} if no block holds that key.
     */
    String removePairingBlockByKey(String publicKeyHex);

    /** Remove all pairing blocks ("empty the store"). Returns the number of blocks removed. */
    int clearPairingBlocks();

    // --- Confirm pairing ---

    /** Whether a pairing confirmation is currently awaiting an operator decision. */
    boolean isPairingPending();

    /** The pending pairing prompt (e.g. "Pair with &lt;label&gt;"), or "" if none is pending. */
    String getPairingPrompt();

    /** Confirm the pending pairing. Throws {@link IllegalStateException} if none is pending. */
    void confirmPairing();

    /** Reject the pending pairing. Throws {@link IllegalStateException} if none is pending. */
    void rejectPairing();

    // --- Enter a PIN ---

    /** Whether a host PIN entry is currently awaiting input. */
    boolean isPinPending();

    /** The pending PIN prompt (slot/reference info), or "" if none is pending. */
    String getPinPrompt();

    /** Supply the PIN for the pending PERFORM VERIFICATION. Throws if none is pending. */
    void enterPin(String pin);

    /** Cancel the pending PIN entry (treated as a timeout/abort). Throws if none is pending. */
    void cancelPin();

    // --- gSMC-KT certificate ---

    /** Subject DN of the SM-KT authentication certificate the terminal presents. */
    String getGsmcKtSubject();

    /** Issuer DN of the SM-KT authentication certificate. */
    String getGsmcKtIssuer();

    /** Serial number (hex) of the SM-KT authentication certificate. */
    String getGsmcKtSerial();

    /** Key type of the presented identity ("EC" or "RSA"). */
    String getGsmcKtKeyType();

    /** {@code notBefore} of the SM-KT certificate (ISO-8601). */
    String getGsmcKtValidFrom();

    /** {@code notAfter} of the SM-KT certificate (ISO-8601). */
    String getGsmcKtValidUntil();

    /** The SM-KT authentication certificate as a PEM-encoded string. */
    String getGsmcKtCertificatePem();

    // --- Lifecycle ---

    /** Restart the terminal (relaunch the process with the same configuration). */
    String restart();

    /**
     * Restart the terminal after wiping all pairing blocks (factory defaults). All Konnektoren must
     * pair again afterwards.
     */
    String restartWithFactoryDefaults();
}
