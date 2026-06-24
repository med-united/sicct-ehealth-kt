package de.servicehealtherx.ehealthkt.card;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * Binds each connected PC/SC reader to a card slot. Slot indices are 1-based in the order
 * the platform reports the readers.
 */
public class PcscCardSlotBackend implements CardSlotBackend {

    private static final Logger log = LoggerFactory.getLogger(PcscCardSlotBackend.class);

    private final List<CardSlot> slots = new ArrayList<>();

    public PcscCardSlotBackend() {
        try {
            CardTerminals terminals = TerminalFactory.getDefault().terminals();
            int index = 1;
            for (CardTerminal terminal : terminals.list()) {
                log.info("Binding slot {} to PC/SC reader '{}'", index, terminal.getName());
                slots.add(new PcscCardSlot(index++, terminal));
            }
            if (slots.isEmpty()) {
                log.warn("No PC/SC readers found");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not enumerate PC/SC readers", e);
        }
    }

    @Override
    public List<CardSlot> slots() {
        return slots;
    }
}
