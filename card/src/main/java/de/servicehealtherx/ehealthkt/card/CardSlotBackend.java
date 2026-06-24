package de.servicehealtherx.ehealthkt.card;

import java.util.List;
import java.util.Optional;

/**
 * Source of the terminal's card slots. Implementations bind slots to physical PC/SC
 * readers ({@link PcscCardSlotBackend}) or to simulated cards ({@link SimulatedCardSlotBackend}).
 */
public interface CardSlotBackend extends AutoCloseable {

    /** All slots, ordered by index. */
    List<CardSlot> slots();

    /** The slot with the given 1-based index, if any. */
    default Optional<CardSlot> slot(int index) {
        return slots().stream().filter(s -> s.index() == index).findFirst();
    }

    @Override
    default void close() {
    }
}
