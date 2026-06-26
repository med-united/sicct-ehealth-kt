package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.card.SimulatedCardSlotBackend;
import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.sicct.EventTag;
import de.servicehealtherx.ehealthkt.sicct.MessageType;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CardPresenceMonitorTest {

    @Test
    void emitsCardInsertedAndRemovedOnTransitionsButNotForBaseline() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        CardSlotManager cards = new CardSlotManager(backend);
        SicctSessionRegistry sessions = new SicctSessionRegistry();
        EmbeddedChannel konnektor = new EmbeddedChannel();
        sessions.register(konnektor);

        // Interval 0 disables the background thread so we drive poll() deterministically.
        CardPresenceMonitor monitor = new CardPresenceMonitor(cards, sessions, 0);

        // First poll establishes the baseline (both slots empty) — no events.
        monitor.poll();
        assertThat((SicctMessage) konnektor.readOutbound()).isNull();

        // A card is inserted into slot 2 -> a single CARD_INSERTED event addressing slot 2.
        backend.simulatedSlot(2).insert(ScriptedVirtualCard.egk());
        monitor.poll();
        SicctMessage inserted = konnektor.readOutbound();
        assertThat(inserted).isNotNull();
        assertThat(inserted.type()).isEqualTo(MessageType.EVENT);
        assertThat(inserted.getBody())
                .isEqualTo(new byte[]{EventTag.CARD_INSERTED.value(), 0x02, 0x00, 0x02});
        assertThat((SicctMessage) konnektor.readOutbound()).isNull(); // exactly one event

        // No change between polls -> no event.
        monitor.poll();
        assertThat((SicctMessage) konnektor.readOutbound()).isNull();

        // The card is removed -> a single CARD_REMOVED event addressing slot 2.
        backend.simulatedSlot(2).remove();
        monitor.poll();
        SicctMessage removed = konnektor.readOutbound();
        assertThat(removed).isNotNull();
        assertThat(removed.getBody())
                .isEqualTo(new byte[]{EventTag.CARD_REMOVED.value(), 0x02, 0x00, 0x02});
    }

    @Test
    void cardRemovedRaisesEventImmediatelyAndPollDoesNotDuplicateIt() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(1);
        backend.simulatedSlot(1).insert(ScriptedVirtualCard.egk());
        CardSlotManager cards = new CardSlotManager(backend);
        SicctSessionRegistry sessions = new SicctSessionRegistry();
        EmbeddedChannel konnektor = new EmbeddedChannel();
        sessions.register(konnektor);

        CardPresenceMonitor monitor = new CardPresenceMonitor(cards, sessions, 0);
        monitor.poll(); // baseline: card present in slot 1, no event
        assertThat((SicctMessage) konnektor.readOutbound()).isNull();

        // A command detects the card was pulled -> CARD REMOVED raised immediately.
        backend.simulatedSlot(1).remove();
        monitor.cardRemoved(1);
        SicctMessage removed = konnektor.readOutbound();
        assertThat(removed).isNotNull();
        assertThat(removed.type()).isEqualTo(MessageType.EVENT);
        assertThat(removed.getBody())
                .isEqualTo(new byte[]{EventTag.CARD_REMOVED.value(), 0x02, 0x00, 0x01});

        // The next presence poll sees the slot already known-absent -> no duplicate event.
        monitor.poll();
        assertThat((SicctMessage) konnektor.readOutbound()).isNull();
    }

    @Test
    void deliversEventsToEveryActiveSessionAndStopsAfterUnregister() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(1);
        CardSlotManager cards = new CardSlotManager(backend);
        SicctSessionRegistry sessions = new SicctSessionRegistry();
        EmbeddedChannel a = new EmbeddedChannel();
        EmbeddedChannel b = new EmbeddedChannel();
        sessions.register(a);
        sessions.register(b);

        CardPresenceMonitor monitor = new CardPresenceMonitor(cards, sessions, 0);
        monitor.poll(); // baseline

        backend.simulatedSlot(1).insert(ScriptedVirtualCard.egk());
        monitor.poll();
        assertThat((SicctMessage) a.readOutbound()).isNotNull();
        assertThat((SicctMessage) b.readOutbound()).isNotNull();

        // After b leaves, only a keeps receiving events.
        sessions.unregister(b);
        backend.simulatedSlot(1).remove();
        monitor.poll();
        assertThat((SicctMessage) a.readOutbound()).isNotNull();
        assertThat((SicctMessage) b.readOutbound()).isNull();
    }
}
