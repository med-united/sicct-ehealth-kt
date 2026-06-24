package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.sicct.IccStatus;

import java.util.List;
import java.util.Optional;

/**
 * Owns the terminal's card slots and exposes the operations the SICCT command interpreter needs:
 * powering cards on/off (REQUEST/RESET/EJECT ICC), transmitting APDUs and querying status.
 * Backed by a {@link CardSlotBackend} (PC/SC or simulated).
 */
public class CardSlotManager implements AutoCloseable {

    private final CardSlotBackend backend;

    public CardSlotManager(CardSlotBackend backend) {
        this.backend = backend;
    }

    public List<CardSlot> slots() {
        return backend.slots();
    }

    public Optional<CardSlot> slot(int index) {
        return backend.slot(index);
    }

    private CardSlot require(int index) {
        return backend.slot(index)
                .orElseThrow(() -> new IllegalArgumentException("No such slot: " + index));
    }

    /** SICCT REQUEST ICC / RESET CT: power on the card and return its status. */
    public IccStatus requestIcc(int slot) {
        return require(slot).reset();
    }

    /** SICCT EJECT ICC: power off the card. */
    public void ejectIcc(int slot) {
        require(slot).eject();
    }

    public IccStatus iccStatus(int slot) {
        return slot(slot).map(CardSlot::status).orElse(IccStatus.CC_UNKNOWN);
    }

    public byte[] atr(int slot) {
        return require(slot).atr();
    }

    /** Transmit a command APDU to the addressed slot and return the response APDU. */
    public byte[] transmit(int slot, byte[] commandApdu) {
        return require(slot).transmit(commandApdu);
    }

    public boolean supportsSecurePinEntry(int slot) {
        return slot(slot).map(CardSlot::supportsSecurePinEntry).orElse(false);
    }

    public byte[] verifyPinSecure(int slot, byte pinReference) {
        return require(slot).verifyPinSecure(pinReference);
    }

    public byte[] verifyPinPlain(int slot, byte pinReference, String pin) {
        return require(slot).verifyPinPlain(pinReference, pin);
    }

    @Override
    public void close() throws Exception {
        backend.close();
    }
}
