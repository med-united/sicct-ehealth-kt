package de.servicehealtherx.ehealthkt.card;

/**
 * Notified when a card slot detects mid-operation that its card has been removed. Allows the
 * terminal layer to raise a SICCT CARD REMOVED event immediately, instead of waiting for the
 * next presence poll. Registered on {@link CardSlotManager#setRemovalListener(CardRemovalListener)}.
 */
@FunctionalInterface
public interface CardRemovalListener {

    /** Invoked with the 1-based slot index whose card was just found to be removed. */
    void cardRemoved(int slot);
}
