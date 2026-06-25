package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.gsmckt.TerminalIdentity;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.StatusWord;
import de.servicehealtherx.ehealthkt.sicct.Tlv;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingStore;
import de.servicehealtherx.ehealthkt.ui.TerminalUi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;

/**
 * Implements EHEALTH TERMINAL AUTHENTICATE (gemSpec_KT 3.7.2): the pairing protocol between a
 * Konnektor and the eHealth-KT.
 *
 * <ul>
 *   <li><b>CREATE (P2=01)</b>: Konnektor sends a 16-byte shared secret (DO 0xD4) and an application
 *   label (DO 0x50). After user confirmation, the terminal stores a pairing block bound to the
 *   Konnektor's TLS public key and returns the gSMC-KT signature over the shared secret.</li>
 *   <li><b>VALIDATE (P2=02)</b>: Konnektor sends a challenge (DO 0xD5, 16..127 bytes). The terminal
 *   returns SHA-256(challenge || shared secret) for the pairing bound to the Konnektor's key.</li>
 *   <li><b>ADD Phase 1 (P2=03)</b>: the terminal draws a challenge of {@code Le} bytes from the
 *   SM-KT RNG, remembers it (state "EHEALTH EXPECT CHALLENGE RESPONSE", owned by the connection
 *   handler) and returns it.</li>
 *   <li><b>ADD Phase 2 (P2=04)</b>: Konnektor returns SHA-256(challenge || shared secret) (DO 0xD6,
 *   32 bytes). The terminal recomputes the hash for every stored pairing block; on a unique match it
 *   binds the Konnektor's current TLS public key to that block (adding an additional Konnektor to an
 *   existing shared secret).</li>
 * </ul>
 *
 * Each method returns the raw response payload (signature/hash) or a 2-byte error status word.
 */
public class EhealthTerminalAuthenticate {

    private static final int TAG_SHARED_SECRET = 0xD4;
    private static final int TAG_APPLICATION_LABEL = 0x50;
    private static final int TAG_SHARED_SECRET_CHALLENGE = 0xD5;
    private static final int TAG_SHARED_SECRET_RESPONSE = 0xD6;

    /** Minimum challenge length for ADD Phase 1 (gemSpec_KT SEQ_KT_0003 step 1, Le range '10'..'7F'). */
    private static final int MIN_CHALLENGE_LENGTH = 16;
    private static final int MAX_CHALLENGE_LENGTH = 127;
    /** The Shared Secret Response DO carries a SHA-256 hash, i.e. exactly 32 bytes. */
    private static final int SHARED_SECRET_RESPONSE_LENGTH = 32;

    private static final Logger log = LoggerFactory.getLogger(EhealthTerminalAuthenticate.class);

    private final TerminalIdentity identity;
    private final PairingStore pairingStore;
    private final TerminalUi ui;

    public EhealthTerminalAuthenticate(TerminalIdentity identity, PairingStore pairingStore, TerminalUi ui) {
        this.identity = identity;
        this.pairingStore = pairingStore;
        this.ui = ui;
    }

    /** CREATE (P2=01). {@code clientPublicKeyHex} is the encoded Konnektor TLS public key. */
    public byte[] create(byte[] commandData, String clientPublicKeyHex) {
        List<Tlv> tlvs = Tlv.parseList(commandData);
        Tlv secretTlv = Tlv.find(tlvs, TAG_SHARED_SECRET);
        Tlv labelTlv = Tlv.find(tlvs, TAG_APPLICATION_LABEL);
        if (secretTlv == null || labelTlv == null) {
            log.warn("CREATE missing shared secret or application label");
            return StatusWord.REFERENCED_DATA_NOT_FOUND.toBytes();
        }
        if (secretTlv.value().length != 16) {
            log.warn("CREATE shared secret must be 16 bytes, was {}", secretTlv.value().length);
            return StatusWord.INCORRECT_DATA_FIELD.toBytes();
        }
        String label = new String(labelTlv.value(), java.nio.charset.StandardCharsets.US_ASCII);

        if (!ui.confirm("Pair with", label)) {
            log.info("CREATE cancelled by user");
            return StatusWord.COMMAND_TIMEOUT.toBytes();
        }

        String secretHex = Hex.toHex(secretTlv.value());
        PairingBlock block = new PairingBlock(secretHex);
        block.addPublicKey(clientPublicKeyHex);
        pairingStore.add(block);
        log.info("Paired with '{}' (key {}…)", label, clientPublicKeyHex.substring(0, Math.min(12, clientPublicKeyHex.length())));

        // Response APDU = <gSMC-KT signature over the shared secret> SW1 SW2, terminated by 9000
        // like every ISO-7816 response so the Konnektor can split off the trailer (the data field
        // before it is the signature).
        return Hex.concat(identity.signPairingSecret(secretTlv.value()), StatusWord.SUCCESS.toBytes());
    }

    /** VALIDATE (P2=02). */
    public byte[] validate(byte[] commandData, String clientPublicKeyHex) {
        List<Tlv> tlvs = Tlv.parseList(commandData);
        Tlv challengeTlv = Tlv.find(tlvs, TAG_SHARED_SECRET_CHALLENGE);
        if (challengeTlv == null) {
            log.warn("VALIDATE missing shared secret challenge");
            return StatusWord.REFERENCED_DATA_NOT_FOUND.toBytes();
        }
        int len = challengeTlv.value().length;
        if (len < 16 || len > 127) {
            log.warn("VALIDATE challenge length out of range: {}", len);
            return StatusWord.INCORRECT_DATA_FIELD.toBytes();
        }
        Optional<PairingBlock> block = pairingStore.findByPublicKey(clientPublicKeyHex);
        if (block.isEmpty()) {
            log.warn("VALIDATE no pairing for key {}", clientPublicKeyHex);
            return StatusWord.COMMAND_NOT_ALLOWED.toBytes();
        }
        byte[] hash = sharedSecretHash(challengeTlv.value(), block.get());
        if (hash == null) {
            return StatusWord.COMMAND_NOT_ALLOWED.toBytes();
        }
        // Response APDU = <SHA-256(challenge || shared secret)> SW1 SW2, terminated by 9000.
        return Hex.concat(hash, StatusWord.SUCCESS.toBytes());
    }

    /**
     * ADD Phase 1 (P2=03). Draw a challenge of {@code requestedLength} bytes from the SM-KT RNG.
     * Returns the challenge on success, or {@code null} if {@code requestedLength} is out of the
     * permitted range (the caller maps that to a wrong-length status word and stays out of the
     * EHEALTH EXPECT CHALLENGE RESPONSE state).
     */
    public byte[] addPhase1(int requestedLength) {
        if (requestedLength < MIN_CHALLENGE_LENGTH || requestedLength > MAX_CHALLENGE_LENGTH) {
            log.warn("ADD Phase 1 requested challenge length {} out of range [{}, {}]",
                    requestedLength, MIN_CHALLENGE_LENGTH, MAX_CHALLENGE_LENGTH);
            return null;
        }
        return identity.randomBytes(requestedLength);
    }

    /**
     * ADD Phase 2 (P2=04). {@code challenge} is the value generated in Phase 1; {@code commandData}
     * carries the Shared Secret Response DO (0xD6); {@code clientPublicKeyHex} is the encoded
     * Konnektor TLS public key from the current handshake. On a unique match the Konnektor key is
     * bound to the matching pairing block and SW 9000 is returned; otherwise a 2-byte error status.
     */
    public byte[] addPhase2(byte[] challenge, byte[] commandData, String clientPublicKeyHex) {
        List<Tlv> tlvs = Tlv.parseList(commandData);
        Tlv responseTlv = Tlv.find(tlvs, TAG_SHARED_SECRET_RESPONSE);
        if (responseTlv == null) {
            log.warn("ADD Phase 2 missing shared secret response");
            return StatusWord.REFERENCED_DATA_NOT_FOUND.toBytes();
        }
        if (responseTlv.value().length != SHARED_SECRET_RESPONSE_LENGTH) {
            log.warn("ADD Phase 2 shared secret response must be {} bytes, was {}",
                    SHARED_SECRET_RESPONSE_LENGTH, responseTlv.value().length);
            return StatusWord.INCORRECT_DATA_FIELD.toBytes();
        }
        byte[] expected = responseTlv.value();

        // Recompute SHA-256(challenge || shared secret) for every block; require a unique match.
        PairingBlock match = null;
        for (PairingBlock block : pairingStore.all()) {
            byte[] hash = sharedSecretHash(challenge, block);
            if (hash != null && java.security.MessageDigest.isEqual(hash, expected)) {
                if (match != null) {
                    log.warn("ADD Phase 2 hash matched more than one pairing block; rejecting");
                    return StatusWord.NO_INFORMATION.toBytes();
                }
                match = block;
            }
        }
        if (match == null) {
            log.warn("ADD Phase 2 no pairing block matched the shared secret response");
            return StatusWord.NO_INFORMATION.toBytes();
        }

        // If the new key already lives in a different block, remove it there before binding it here.
        for (PairingBlock other : pairingStore.all()) {
            if (other != match) {
                other.removePublicKey(clientPublicKeyHex);
            }
        }
        match.bindPublicKey(clientPublicKeyHex);
        pairingStore.update(match);
        log.info("ADD: bound Konnektor key {}… to existing pairing block",
                clientPublicKeyHex.substring(0, Math.min(12, clientPublicKeyHex.length())));
        return StatusWord.SUCCESS.toBytes();
    }

    /**
     * SHA-256(challenge || shared secret of {@code block}), i.e. the raw 32-byte hash; {@code null}
     * if the digest could not be computed. Callers append the response status word themselves
     * (VALIDATE) or compare the hash directly (ADD Phase 2), so this returns the bare hash.
     */
    private byte[] sharedSecretHash(byte[] challenge, PairingBlock block) {
        byte[] secret = Hex.toBytes(block.getSharedSecretHex());
        try {
            return MessageDigest.getInstance("SHA-256").digest(Hex.concat(challenge, secret));
        } catch (Exception e) {
            log.error("Could not compute shared secret hash", e);
            return null;
        }
    }
}
