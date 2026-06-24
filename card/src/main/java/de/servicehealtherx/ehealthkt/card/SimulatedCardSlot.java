package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.card.sim.VirtualCard;
import de.servicehealtherx.ehealthkt.sicct.IccStatus;

/**
 * A simulated card slot driven by a {@link VirtualCard}. Has no PIN pad, so PIN verification
 * always uses the plain (remote/host) path.
 */
public class SimulatedCardSlot implements CardSlot {

    private final int index;
    private VirtualCard card;
    private boolean powered;

    public SimulatedCardSlot(int index) {
        this.index = index;
    }

    public SimulatedCardSlot(int index, VirtualCard card) {
        this.index = index;
        this.card = card;
    }

    /** Insert a simulated card (test/demo control). */
    public synchronized void insert(VirtualCard card) {
        this.card = card;
        this.powered = false;
    }

    /** Physically remove the simulated card. */
    public synchronized void remove() {
        this.card = null;
        this.powered = false;
    }

    @Override
    public int index() {
        return index;
    }

    @Override
    public boolean isPresent() {
        return card != null;
    }

    @Override
    public IccStatus status() {
        if (card == null) {
            return IccStatus.CC_ABSENT;
        }
        return powered ? IccStatus.CC_SPECIFIC : IccStatus.CC_PRESENT;
    }

    @Override
    public byte[] atr() {
        return (card != null && powered) ? card.atr() : null;
    }

    @Override
    public synchronized IccStatus reset() {
        if (card == null) {
            return IccStatus.CC_ABSENT;
        }
        powered = true;
        return IccStatus.CC_SPECIFIC;
    }

    @Override
    public synchronized void eject() {
        powered = false;
    }

    @Override
    public byte[] transmit(byte[] commandApdu) {
        if (card == null) {
            throw new IllegalStateException("No card present in simulated slot " + index);
        }
        if (!powered) {
            reset();
        }
        return card.transmit(commandApdu);
    }

    @Override
    public boolean supportsSecurePinEntry() {
        return false;
    }

    @Override
    public byte[] verifyPinSecure(byte pinReference) {
        throw new UnsupportedOperationException("Simulated slot has no PIN pad");
    }

    @Override
    public byte[] verifyPinPlain(byte pinReference, String pin) {
        return transmit(PinBlocks.verifyApdu(pinReference, pin));
    }
}
