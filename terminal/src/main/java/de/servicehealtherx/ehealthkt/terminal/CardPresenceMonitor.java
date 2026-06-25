package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardSlot;
import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.sicct.EventTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Watches every card slot for card insertion and removal and emits the matching SICCT events
 * ({@link EventTag#CARD_INSERTED} / {@link EventTag#CARD_REMOVED}) to all active sessions via the
 * {@link SicctSessionRegistry}.
 *
 * <p>A slot's presence on first observation is taken as the baseline (no event), so a card already
 * seated at start-up — including the gSMC-KT — does not raise a spurious event; only genuine
 * transitions afterwards do. Slots from readers hot-plugged after start-up are picked up
 * automatically (their first poll is their baseline).
 */
public class CardPresenceMonitor implements AutoCloseable {

    /** How often the slots are polled for insertion/removal, in milliseconds. */
    public static final long DEFAULT_POLL_INTERVAL_MS = 1_000;

    private static final Logger log = LoggerFactory.getLogger(CardPresenceMonitor.class);

    private final CardSlotManager cards;
    private final SicctSessionRegistry sessions;
    private final ScheduledExecutorService scheduler;
    private final Map<Integer, Boolean> presentBySlot = new HashMap<>();

    public CardPresenceMonitor(CardSlotManager cards, SicctSessionRegistry sessions) {
        this(cards, sessions, DEFAULT_POLL_INTERVAL_MS);
    }

    /**
     * @param pollIntervalMs polling period; {@code <= 0} disables the background thread (the caller
     *                       then drives {@link #poll()} itself, e.g. from a test).
     */
    public CardPresenceMonitor(CardSlotManager cards, SicctSessionRegistry sessions, long pollIntervalMs) {
        this.cards = cards;
        this.sessions = sessions;
        if (pollIntervalMs > 0) {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "card-presence-monitor");
                t.setDaemon(true);
                return t;
            });
            scheduler.scheduleWithFixedDelay(this::pollQuietly, pollIntervalMs, pollIntervalMs,
                    TimeUnit.MILLISECONDS);
        } else {
            scheduler = null;
        }
    }

    /** Poll once: detect insert/remove transitions since the last poll and broadcast the events. */
    void poll() {
        for (CardSlot slot : cards.slots()) {
            int index = slot.index();
            boolean present = slot.isPresent();
            Boolean previous = presentBySlot.put(index, present);
            if (previous == null || previous == present) {
                continue; // first sighting (baseline) or no change
            }
            EventTag tag = present ? EventTag.CARD_INSERTED : EventTag.CARD_REMOVED;
            log.info("Slot {}: card {} — notifying {} session(s)", index,
                    present ? "inserted" : "removed", sessions.size());
            sessions.broadcastCardEvent(tag, index);
        }
    }

    private void pollQuietly() {
        try {
            poll();
        } catch (Exception e) {
            log.debug("Card presence poll failed", e);
        }
    }

    @Override
    public void close() {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }
}
