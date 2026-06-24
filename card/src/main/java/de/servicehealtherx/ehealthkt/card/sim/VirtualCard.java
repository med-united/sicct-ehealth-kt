package de.servicehealtherx.ehealthkt.card.sim;

/**
 * A simulated card: responds to command APDUs and exposes an ATR. Used by
 * {@link de.servicehealtherx.ehealthkt.card.SimulatedCardSlotBackend} for hardware-free runs.
 */
public interface VirtualCard {

    byte[] atr();

    /** Process a command APDU and return the response APDU (data + SW1 SW2). */
    byte[] transmit(byte[] commandApdu);
}
