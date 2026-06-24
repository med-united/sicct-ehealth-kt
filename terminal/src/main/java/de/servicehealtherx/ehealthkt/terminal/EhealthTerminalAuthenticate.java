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
 * </ul>
 *
 * Each method returns the raw response payload (signature/hash) or a 2-byte error status word.
 */
public class EhealthTerminalAuthenticate {

    private static final int TAG_SHARED_SECRET = 0xD4;
    private static final int TAG_APPLICATION_LABEL = 0x50;
    private static final int TAG_SHARED_SECRET_CHALLENGE = 0xD5;

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

        return identity.signPairingSecret(secretTlv.value());
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
        // SHA-256(challenge || shared secret)
        byte[] secret = Hex.toBytes(block.get().getSharedSecretHex());
        byte[] toHash = Hex.concat(challengeTlv.value(), secret);
        try {
            return MessageDigest.getInstance("SHA-256").digest(toHash);
        } catch (Exception e) {
            log.error("VALIDATE could not hash", e);
            return StatusWord.COMMAND_NOT_ALLOWED.toBytes();
        }
    }
}
