package de.servicehealtherx.ehealthkt.card;

import java.util.ArrayList;
import java.util.List;

/**
 * A backend with a fixed number of {@link SimulatedCardSlot}s for hardware-free runs and tests.
 */
public class SimulatedCardSlotBackend implements CardSlotBackend {

    private final List<CardSlot> slots = new ArrayList<>();

    public SimulatedCardSlotBackend(int slotCount) {
        for (int i = 1; i <= slotCount; i++) {
            slots.add(new SimulatedCardSlot(i));
        }
    }

    @Override
    public List<CardSlot> slots() {
        return slots;
    }

    /** Convenience accessor returning the typed simulated slot. */
    public SimulatedCardSlot simulatedSlot(int index) {
        return (SimulatedCardSlot) slot(index)
                .orElseThrow(() -> new IllegalArgumentException("No simulated slot " + index));
    }
}
