package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.sicct.IccStatus;

/**
 * A card slot for the terminal's own <b>gSMC-KT</b>, exposing it like any other ICC so a Konnektor
 * can discover and address it over SICCT (conventionally slot 1 of a real terminal).
 *
 * <p>Unlike {@link PcscCardSlot}, this slot does <b>not</b> open its own PC/SC connection: the
 * gSMC-KT's card is already held by the terminal's TLS identity, and a second connection issuing
 * APDUs concurrently with TLS signing corrupts the card's T=1 exchange (the Konnektor then sees a
 * TLS {@code internal_error} and the connection drops). Instead it forwards APDUs through the shared
 * {@link CardApduTransmitter} the identity provides, which serialises them against TLS/pairing
 * signing on the same channel. For the same reason the card is never power-cycled or ejected here —
 * it must stay powered for the TLS identity — so {@link #reset()} and {@link #eject()} leave it as is.
 */
public class GsmcKtCardSlot implements CardSlot {

    private final int index;
    private final byte[] atr;
    private final CardApduTransmitter transmitter;

    /**
     * @param index       1-based slot index (the gSMC-KT is conventionally slot 1)
     * @param atr         the gSMC-KT card's ATR, or {@code null} if unavailable
     * @param transmitter shared, serialised APDU channel to the gSMC-KT (the TLS identity)
     */
    public GsmcKtCardSlot(int index, byte[] atr, CardApduTransmitter transmitter) {
        this.index = index;
        this.atr = atr == null ? null : atr.clone();
        this.transmitter = transmitter;
    }

    @Override
    public int index() {
        return index;
    }

    @Override
    public IccStatus status() {
        // The gSMC-KT is always present and powered (the TLS identity holds it connected).
        return IccStatus.CC_SPECIFIC;
    }

    @Override
    public boolean isPresent() {
        return true;
    }

    @Override
    public byte[] atr() {
        return atr == null ? null : atr.clone();
    }

    @Override
    public IccStatus reset() {
        // Never power-cycle the gSMC-KT: the TLS identity owns the connection and a reset would tear
        // down the terminal's own authentication. It is already powered, so just report its status.
        return status();
    }

    @Override
    public void eject() {
        // No-op: the gSMC-KT must stay powered for the TLS identity.
    }

    @Override
    public byte[] transmit(byte[] commandApdu) {
        return transmitter.transmit(commandApdu);
    }

    @Override
    public boolean supportsSecurePinEntry() {
        return false;
    }

    @Override
    public byte[] verifyPinSecure(byte pinReference) {
        throw new UnsupportedOperationException("gSMC-KT slot has no PIN pad");
    }

    @Override
    public byte[] verifyPinPlain(byte pinReference, String pin) {
        throw new UnsupportedOperationException("gSMC-KT has no user PIN");
    }
}
