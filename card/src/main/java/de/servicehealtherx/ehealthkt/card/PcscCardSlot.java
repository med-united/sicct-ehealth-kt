package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.sicct.IccStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;

/**
 * A card slot backed by a physical PC/SC reader ({@code javax.smartcardio}).
 * Supports secure PIN entry via the CCID {@code FEATURE_VERIFY_PIN_DIRECT} feature
 * when the reader exposes a PIN pad.
 */
public class PcscCardSlot implements CardSlot {

    private static final byte FEATURE_VERIFY_PIN_DIRECT = 0x06;

    private static final Logger log = LoggerFactory.getLogger(PcscCardSlot.class);

    private final int index;
    private final CardTerminal terminal;

    private Card card;
    private CardChannel channel;

    public PcscCardSlot(int index, CardTerminal terminal) {
        this.index = index;
        this.terminal = terminal;
    }

    @Override
    public int index() {
        return index;
    }

    @Override
    public boolean isPresent() {
        try {
            return terminal.isCardPresent();
        } catch (CardException e) {
            return false;
        }
    }

    @Override
    public IccStatus status() {
        if (!isPresent()) {
            return IccStatus.CC_ABSENT;
        }
        return channel != null ? IccStatus.CC_SPECIFIC : IccStatus.CC_PRESENT;
    }

    @Override
    public byte[] atr() {
        return card != null ? card.getATR().getBytes() : null;
    }

    @Override
    public IccStatus reset() {
        try {
            if (card != null) {
                eject();
            }
            card = terminal.connect("*");
            channel = card.getBasicChannel();
            return IccStatus.CC_SPECIFIC;
        } catch (CardException e) {
            log.warn("Could not power on card in slot {}", index, e);
            return isPresent() ? IccStatus.CC_PRESENT : IccStatus.CC_ABSENT;
        }
    }

    @Override
    public void eject() {
        try {
            if (card != null) {
                card.disconnect(false);
            }
        } catch (CardException e) {
            log.debug("Error disconnecting card in slot {}", index, e);
        } finally {
            card = null;
            channel = null;
        }
    }

    @Override
    public byte[] transmit(byte[] commandApdu) {
        ensurePowered();
        try {
            return channel.transmit(new CommandAPDU(commandApdu)).getBytes();
        } catch (CardException e) {
            throw new IllegalStateException("APDU transmit failed on slot " + index, e);
        }
    }

    @Override
    public boolean supportsSecurePinEntry() {
        try {
            ensurePowered();
            featureControlCode();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public byte[] verifyPinSecure(byte pinReference) {
        ensurePowered();
        try {
            int controlCode = featureControlCode();
            return card.transmitControlCommand(controlCode, PinBlocks.pinVerifyStructure(pinReference));
        } catch (CardException e) {
            throw new IllegalStateException("Secure PIN verify failed on slot " + index, e);
        }
    }

    @Override
    public byte[] verifyPinPlain(byte pinReference, String pin) {
        return transmit(PinBlocks.verifyApdu(pinReference, pin));
    }

    private void ensurePowered() {
        if (channel == null) {
            reset();
        }
        if (channel == null) {
            throw new IllegalStateException("No card powered in slot " + index);
        }
    }

    private int featureControlCode() throws CardException {
        byte[] features = card.transmitControlCommand(scardCtlCode(3400), new byte[0]);
        for (int i = 0; i + 5 < features.length; i += 6) {
            if (features[i] == FEATURE_VERIFY_PIN_DIRECT) {
                return ((features[i + 2] & 0xFF) << 24)
                        | ((features[i + 3] & 0xFF) << 16)
                        | ((features[i + 4] & 0xFF) << 8)
                        | (features[i + 5] & 0xFF);
            }
        }
        throw new CardException("Reader does not expose FEATURE_VERIFY_PIN_DIRECT");
    }

    private static int scardCtlCode(int code) {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            return 0x00310000 | (code << 2);
        }
        return 0x42000000 + code;
    }
}
