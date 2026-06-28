package de.servicehealtherx.ehealthkt.card;

import java.util.ArrayList;
import java.util.List;

/**
 * A {@link CardSlotBackend} that prepends a set of fixed slots (e.g. the gSMC-KT, slot 1) to those
 * of a delegate backend (e.g. the PC/SC card readers, slots 2..n). The fixed slots come first so the
 * slot list order — which the SICCT GET STATUS ALL ICC response is built from positionally — matches
 * the slots' 1-based indices.
 */
public class CompositeCardSlotBackend implements CardSlotBackend {

    private final List<CardSlot> fixedSlots;
    private final CardSlotBackend delegate;

    public CompositeCardSlotBackend(List<CardSlot> fixedSlots, CardSlotBackend delegate) {
        this.fixedSlots = List.copyOf(fixedSlots);
        this.delegate = delegate;
    }

    @Override
    public List<CardSlot> slots() {
        List<CardSlot> all = new ArrayList<>(fixedSlots);
        all.addAll(delegate.slots());
        return all;
    }

    @Override
    public void close() {
        delegate.close();
    }
}
