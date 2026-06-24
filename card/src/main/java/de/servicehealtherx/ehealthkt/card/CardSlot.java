package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.sicct.IccStatus;

/**
 * A single ICC contact unit (card slot) of the terminal. Slots are numbered 1..n
 * (slot 1 is conventionally the gSMC-KT in a real terminal).
 */
public interface CardSlot {

    /** 1-based slot index as referenced on the SICCT wire. */
    int index();

    /** Current ICC status of the slot. */
    IccStatus status();

    /** Whether a card is physically present. */
    boolean isPresent();

    /** The ATR of the powered card, or {@code null} if no card / not powered. */
    byte[] atr();

    /**
     * Power on / reset the card and return the resulting status. Equivalent to SICCT
     * REQUEST ICC: makes the card available and returns its ATR via {@link #atr()}.
     */
    IccStatus reset();

    /** Power off the card (SICCT EJECT ICC). The card stays physically present. */
    void eject();

    /** Transmit a raw command APDU to the card and return the raw response APDU. */
    byte[] transmit(byte[] commandApdu);

    /** Whether the underlying reader provides a secure PIN pad (class-2/3 reader). */
    boolean supportsSecurePinEntry();

    /**
     * Verify a PIN using the reader's own PIN pad (secure PIN entry). Returns the raw
     * response APDU (status word). Only valid when {@link #supportsSecurePinEntry()}.
     */
    byte[] verifyPinSecure(byte pinReference);

    /**
     * Verify a PIN by sending it (entered on the host / terminal) to the card as a
     * format-2 PIN block. Used as "remote PIN" when the reader has no PIN pad.
     */
    byte[] verifyPinPlain(byte pinReference, String pin);
}
