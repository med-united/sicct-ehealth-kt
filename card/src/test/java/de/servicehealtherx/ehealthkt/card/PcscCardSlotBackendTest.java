package de.servicehealtherx.ehealthkt.card;

import org.junit.jupiter.api.Test;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PcscCardSlotBackendTest {

    /** A reader stub that reports no card present — an empty reader is a valid state. */
    private static CardTerminal reader(String name) {
        return new CardTerminal() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public Card connect(String protocol) throws CardException {
                throw new CardException("no card");
            }

            @Override
            public boolean isCardPresent() {
                return false;
            }

            @Override
            public boolean waitForCardPresent(long timeout) {
                return false;
            }

            @Override
            public boolean waitForCardAbsent(long timeout) {
                return true;
            }
        };
    }

    @Test
    void bindsConnectedReadersToOneBasedSlots() {
        List<CardTerminal> readers = List.of(reader("Reader A"), reader("Reader B"));
        PcscCardSlotBackend backend = new PcscCardSlotBackend(() -> readers, 0);

        List<CardSlot> slots = backend.slots();
        assertThat(slots).hasSize(2);
        assertThat(slots.get(0).index()).isEqualTo(1);
        assertThat(slots.get(1).index()).isEqualTo(2);
        // An empty reader is fine: the slot just reports absent rather than failing.
        assertThat(slots.get(0).isPresent()).isFalse();
    }

    @Test
    void startsWithoutAnyReaderAndPicksUpNewlyConnectedOnes() {
        List<CardTerminal> readers = new ArrayList<>();
        // interval 0 disables the background thread, so we drive the rescan deterministically here.
        PcscCardSlotBackend backend = new PcscCardSlotBackend(() -> List.copyOf(readers), 0);
        assertThat(backend.slots()).isEmpty();

        // A reader is plugged in after start-up.
        readers.add(reader("Hot-plugged Reader"));
        backend.rescanNow();

        assertThat(backend.slots()).hasSize(1);
        assertThat(backend.slots().get(0).index()).isEqualTo(1);

        // Re-scanning again must not rebind the same reader to a new slot.
        backend.rescanNow();
        assertThat(backend.slots()).hasSize(1);
    }
}
