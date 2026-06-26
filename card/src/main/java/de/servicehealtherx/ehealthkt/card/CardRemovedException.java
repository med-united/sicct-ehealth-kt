package de.servicehealtherx.ehealthkt.card;

/**
 * Thrown by a {@link CardSlot} when it discovers mid-operation that the card has been physically
 * removed (e.g. a PC/SC {@code transmit} fails with "Card has been removed"). The slot clears its
 * own powered channel before throwing, so the next {@link CardSlot#reset()} re-establishes a fresh
 * channel once a card is present again.
 *
 * <p>{@link CardSlotManager} translates this into a {@link CardRemovalListener#cardRemoved(int)}
 * notification so a SICCT CARD REMOVED event can be raised at the moment the removal is detected.
 */
public class CardRemovedException extends IllegalStateException {

    private final int slot;

    public CardRemovedException(int slot, Throwable cause) {
        super("Card removed from slot " + slot, cause);
        this.slot = slot;
    }

    /** 1-based index of the slot whose card was removed. */
    public int slot() {
        return slot;
    }
}
