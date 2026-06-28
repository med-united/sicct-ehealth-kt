package de.servicehealtherx.ehealthkt.card;

/**
 * Sends a raw command APDU to a card and returns the raw response APDU (data + SW). A seam that lets
 * a {@link CardSlot} drive a card it does not own the connection to — above all the gSMC-KT, whose
 * channel is owned by the terminal's TLS identity ({@link GsmcKtCardSlot}) — so the card module need
 * not depend on the gsmckt module.
 */
@FunctionalInterface
public interface CardApduTransmitter {

    /**
     * Transmit {@code commandApdu} and return the response APDU.
     *
     * @throws RuntimeException if the transmission fails
     */
    byte[] transmit(byte[] commandApdu);
}
