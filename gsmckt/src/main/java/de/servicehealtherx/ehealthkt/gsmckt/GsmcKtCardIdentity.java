package de.servicehealtherx.ehealthkt.gsmckt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.function.Supplier;

/**
 * A gSMC-KT terminal identity backed by a real card in a PC/SC reader. Ported from the
 * CardLink {@code GSMCktCard}: selects DF.KT, reads the SM-KT AUT certificate, and produces
 * pairing signatures via PSO Compute Digital Signature.
 *
 * <p>APDUs follow gemSpec_COS V3.14.0 and gemSpec_gSMC-KT_ObjSys G2.1 V4.3.0.
 */
public class GsmcKtCardIdentity implements TerminalIdentity {

    private static final Logger log = LoggerFactory.getLogger(GsmcKtCardIdentity.class);

    // SELECT DF.KT (AID D2 76 00 01 44 00)
    private static final byte[] SELECT_DF_KT =
            {0x00, (byte) 0xa4, 0x04, 0x0c, 0x06, (byte) 0xd2, 0x76, 0x00, 0x01, 0x44, 0x00};

    /** Short file identifier of EF.C.SMKT.AUT2 (ECC, brainpoolP256r1) within DF.KT. */
    public static final byte SFI_C_SMKT_AUT2_EC = 0x04;
    /** Short file identifier of EF.C.SMKT.AUT (RSA-2048) within DF.KT. */
    public static final byte SFI_C_SMKT_AUT_RSA = 0x01;

    /** How long to wait for the gSMC-KT to reappear in its reader after it was removed/reset. */
    private static final long RECONNECT_WAIT_MS = 5_000;

    /**
     * The PC/SC reader the card lives in, used to transparently re-open the channel when the card is
     * removed or idle-reset. {@code null} when the identity was bound to a bare channel (the hardware
     * integration test): in that case no automatic reconnect is attempted.
     */
    private final CardTerminal reader;
    /** Re-established by {@link #reconnect()}; read fresh on every transmit so retries use the new card. */
    private volatile CardChannel channel;
    private final KeyType keyType;
    private final X509Certificate certificate;
    private final X509Certificate ecCertificate;
    private final X509Certificate rsaCertificate;

    /**
     * Bind to an already-open card channel. Used by the hardware integration test; does <b>not</b>
     * reconnect automatically if the card is later removed (no reader reference is available).
     */
    public GsmcKtCardIdentity(CardChannel channel) {
        this(channel, null);
    }

    /**
     * Bind to the gSMC-KT in the given PC/SC reader, opening the channel now. If the card is later
     * removed or idle-reset (the gematik gSMC-KT powers down when untouched), signing and slot APDUs
     * transparently re-open the channel and retry once, so the TLS identity survives the card going
     * away and coming back without restarting the terminal.
     */
    public GsmcKtCardIdentity(CardTerminal reader) throws CardException {
        this(reader.connect("*").getBasicChannel(), reader);
    }

    private GsmcKtCardIdentity(CardChannel channel, CardTerminal reader) {
        this.channel = channel;
        this.reader = reader;
        // A gSMC-KT carries both an ECC (EF.C.SMKT.AUT2, SFI 0x04) and an RSA (EF.C.SMKT.AUT,
        // SFI 0x01) authentication certificate. Read both so the TLS server can present either,
        // but prefer the ECC identity for pairing (gematik ECC migration, A_17089-01).
        this.ecCertificate = isEc(tryReadCertificate(SFI_C_SMKT_AUT2_EC));
        this.rsaCertificate = tryReadCertificate(SFI_C_SMKT_AUT_RSA);
        if (ecCertificate != null) {
            this.certificate = ecCertificate;
            this.keyType = KeyType.EC;
        } else if (rsaCertificate != null) {
            this.certificate = rsaCertificate;
            this.keyType = KeyType.RSA;
        } else {
            throw new IllegalStateException("Could not read any SM-KT certificate from gSMC-KT");
        }
        log.info("gSMC-KT identity loaded: preferred keyType={}, EC cert={}, RSA cert={}, subject={}",
                keyType, ecCertificate != null, rsaCertificate != null, certificate.getSubjectX500Principal());
    }

    private static X509Certificate isEc(X509Certificate cert) {
        return cert != null && cert.getPublicKey() instanceof ECPublicKey ? cert : null;
    }

    private X509Certificate tryReadCertificate(byte sfi) {
        try {
            byte[] der = readFileFromDfKt(sfi);
            if (der == null || der.length == 0) {
                return null;
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            log.debug("Could not read certificate from SFI {}", sfi, e);
            return null;
        }
    }

    private byte[] readFileFromDfKt(byte sfi) {
        transmit("SELECT DF.KT", SELECT_DF_KT, false);
        byte[] readBinary = {0x00, (byte) 0xb0, (byte) (0x80 + sfi), 0x00, 0x00, 0x00, 0x00};
        return transmit("READ BINARY", readBinary, true);
    }

    @Override
    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    @Override
    public KeyType getKeyType() {
        return keyType;
    }

    /** The ECC SM-KT certificate (C.SMKT.AUT2, brainpoolP256r1), or {@code null} if the card has none. */
    public X509Certificate getEcCertificate() {
        return ecCertificate;
    }

    /** The RSA SM-KT certificate (C.SMKT.AUT, RSA-2048), or {@code null} if the card has none. */
    public X509Certificate getRsaCertificate() {
        return rsaCertificate;
    }

    /**
     * ECDSA over a pre-computed 32-byte hash with PrK.SMKT.AUT.E256 (brainpoolP256r1); returns the
     * plain {@code r||s} (64 bytes). Used by the TLS server to sign handshake data with the card.
     */
    public byte[] signEcdsa(byte[] hash) {
        return pso(hash, (byte) 0x00, (byte) 0x06);
    }

    /**
     * RSASSA-PKCS1-v1_5 with PrK.SMKT.AUT.R2048 over the supplied DigestInfo (algId 0x02,
     * gemSpec_COS §signPKCS1_V1_5); returns 256 bytes. Used for TLS RSA cipher suites.
     */
    public byte[] signPkcs1(byte[] digestInfo) {
        return pso(digestInfo, (byte) 0x02, (byte) 0x02);
    }

    /**
     * RSASSA-PSS with PrK.SMKT.AUT.R2048 over a pre-computed hash (algId 0x05); returns 256 bytes.
     * The card performs the EMSA-PSS encoding over the given hash.
     */
    public byte[] signPss(byte[] hash) {
        return pso(hash, (byte) 0x05, (byte) 0x02);
    }

    @Override
    public byte[] signPairingSecret(byte[] sharedSecret) {
        if (keyType == KeyType.EC) {
            byte[] hash = sha256(sharedSecret);
            // ECDSA: algId 0x00, keyRef 0x06 -> card returns plain r||s (64 bytes)
            return pso(hash, (byte) 0x00, (byte) 0x06);
        }
        // RSASSA-PSS: algId 0x05, keyRef 0x02 -> 256 bytes
        return pso(sharedSecret, (byte) 0x05, (byte) 0x02);
    }

    /**
     * Draw {@code length} random bytes from the gSMC-KT RNG via GET CHALLENGE (ISO 7816-4,
     * {@code 00 84 00 00 Le}). Falls back to a JCA SecureRandom if the card rejects the command,
     * so the EHEALTH TERMINAL AUTHENTICATE (ADD Phase 1) flow never breaks on RNG availability.
     */
    @Override
    public synchronized byte[] randomBytes(int length) {
        try {
            byte[] getChallenge = {0x00, (byte) 0x84, 0x00, 0x00, (byte) length};
            byte[] random = withReconnect("GET CHALLENGE",
                    () -> transmit("GET CHALLENGE", getChallenge, false));
            if (random != null && random.length == length) {
                return random;
            }
            log.warn("GET CHALLENGE returned {} bytes, expected {}; falling back to SecureRandom",
                    random == null ? 0 : random.length, length);
        } catch (RuntimeException e) {
            log.warn("GET CHALLENGE failed; falling back to SecureRandom", e);
        }
        return TerminalIdentity.super.randomBytes(length);
    }

    /**
     * The ATR of the gSMC-KT card, or {@code null} if unavailable — used to present the card as a
     * SICCT card slot.
     */
    public byte[] atr() {
        try {
            return channel.getCard().getATR().getBytes();
        } catch (RuntimeException e) {
            log.debug("Could not read gSMC-KT ATR", e);
            return null;
        }
    }

    /**
     * Transmit a raw command APDU to the gSMC-KT and return the raw response APDU (data + SW), for
     * exposing the card as a SICCT slot. {@code synchronized} (like the signing operations) so a
     * slot APDU never interleaves with TLS/pairing signing on the shared channel — concurrent access
     * on two halves of one card would corrupt its T=1 exchange.
     */
    public synchronized byte[] transmitApdu(byte[] command) {
        return withReconnect("card APDU", () -> {
            try {
                return channel.transmit(new CommandAPDU(command)).getBytes();
            } catch (CardException e) {
                throw new IllegalStateException("gSMC-KT card APDU transmit failed", e);
            }
        });
    }

    private synchronized byte[] pso(byte[] message, byte algId, byte keyRef) {
        // Run the whole SELECT/MSE/PSO sequence under one reconnect guard: if the card was removed or
        // idle-reset, retrying only the failing APDU would lose the security state set up by the
        // preceding MSE, so the entire sequence must be replayed on the fresh channel.
        return withReconnect("PSO Compute Digital Signature", () -> {
            transmit("SELECT DF.KT", SELECT_DF_KT, false);
            // MSE: select private key + algorithm
            byte[] mse = {0x00, 0x22, 0x41, (byte) 0xB6, 0x06,
                    (byte) 0x84, 0x01, (byte) (0x80 | keyRef), (byte) 0x80, 0x01, algId};
            transmit("MSE", mse, false);

            // PSO Compute Digital Signature, extended length
            ByteArrayOutputStream apdu = new ByteArrayOutputStream();
            apdu.writeBytes(new byte[]{0x00, 0x2a, (byte) 0x9e, (byte) 0x9a});
            apdu.write(0x00); // extended length marker
            apdu.write((message.length >> 8) & 0xFF);
            apdu.write(message.length & 0xFF);
            apdu.writeBytes(message);
            apdu.write(0x00); // Le
            apdu.write(0x00);
            return transmit("PSO Compute Digital Signature", apdu.toByteArray(), false);
        });
    }

    /**
     * Run a card operation; if it fails because the card was removed or idle-reset, transparently
     * re-open the channel (re-discovering the gSMC-KT in its reader) and retry the whole operation
     * once. Only attempted when a {@link #reader} is known; other failures propagate unchanged.
     */
    private <T> T withReconnect(String action, Supplier<T> op) {
        try {
            return op.get();
        } catch (RuntimeException e) {
            if (reader == null || !isCardRemoved(e)) {
                throw e;
            }
            log.warn("gSMC-KT lost during {} ({}); reconnecting to reader '{}' and retrying once",
                    action, rootMessage(e), safeReaderName());
            reconnect();
            return op.get();
        }
    }

    /**
     * Re-open the card channel after the gSMC-KT was removed or reset. Drops the stale handle, waits
     * briefly for a card to be present in the reader (the card may be mid-reinsertion), then connects
     * afresh. The cached certificates are intentionally <b>not</b> re-read so the TLS identity stays
     * stable across the reconnect.
     */
    private synchronized void reconnect() {
        // Drop the dead handle so PC/SC releases the card before we re-power it; best effort.
        try {
            channel.getCard().disconnect(false);
        } catch (Exception ignored) {
            // the card may already be gone
        }
        try {
            if (!reader.isCardPresent()) {
                log.info("Waiting up to {} ms for the gSMC-KT to reappear in reader '{}'",
                        RECONNECT_WAIT_MS, safeReaderName());
                reader.waitForCardPresent(RECONNECT_WAIT_MS);
            }
            this.channel = reader.connect("*").getBasicChannel();
            log.info("Reconnected to gSMC-KT in reader '{}'", safeReaderName());
        } catch (CardException e) {
            throw new IllegalStateException(
                    "Failed to reconnect to gSMC-KT in reader '" + safeReaderName() + "'", e);
        }
    }

    /**
     * Whether a failure means the card went away — removed, reset (the gSMC-KT powers down when idle)
     * or otherwise no longer transacting — so that re-opening the channel can recover it. Walks the
     * cause chain because the trigger surfaces either as a bare {@code IllegalStateException} from
     * {@code CardChannel.transmit} or as a wrapped PC/SC {@link CardException}.
     */
    private static boolean isCardRemoved(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            String m = c.getMessage();
            if (m == null) {
                continue;
            }
            if (m.contains("Card has been removed")
                    || m.contains("SCARD_W_REMOVED_CARD")
                    || m.contains("SCARD_W_RESET_CARD")
                    || m.contains("SCARD_W_UNPOWERED_CARD")
                    || m.contains("SCARD_E_NO_SMARTCARD")
                    || m.contains("SCARD_E_NOT_TRANSACTED")) {
                return true;
            }
        }
        return false;
    }

    private static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null) {
            c = c.getCause();
        }
        return c.getMessage() != null ? c.getMessage() : c.getClass().getSimpleName();
    }

    private String safeReaderName() {
        try {
            return reader.getName();
        } catch (RuntimeException e) {
            return "<unknown>";
        }
    }

    private byte[] transmit(String action, byte[] command, boolean allowNon9000) {
        try {
            ResponseAPDU response = channel.transmit(new CommandAPDU(command));
            if (response.getSW() != 0x9000 && !allowNon9000) {
                throw new IllegalStateException(action + " failed, SW=" + Integer.toHexString(response.getSW()));
            }
            return response.getData();
        } catch (CardException e) {
            throw new IllegalStateException(action + " transmit failed", e);
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        // The card lifecycle (connect/disconnect) is owned by the caller that opened the channel.
    }
}
