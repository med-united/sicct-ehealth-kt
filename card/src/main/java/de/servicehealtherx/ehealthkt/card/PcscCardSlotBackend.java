package de.servicehealtherx.ehealthkt.card;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Binds each connected PC/SC reader to a card slot and keeps that binding up to date: a background
 * task periodically re-enumerates the readers, so a reader plugged in after start-up is bound to a
 * fresh slot automatically. Slot indices are 1-based and handed out in the order readers first
 * appear; an index is never reused, so a slot stays stable for the lifetime of the terminal.
 *
 * <p>An empty reader is perfectly normal: the slot simply reports {@code CC_ABSENT} until a card is
 * inserted (see {@link PcscCardSlot}). The backend never fails just because a reader holds no card.
 */
public class PcscCardSlotBackend implements CardSlotBackend {

    private static final Logger log = LoggerFactory.getLogger(PcscCardSlotBackend.class);

    /** How often the connected PC/SC readers are re-enumerated, in milliseconds. */
    public static final long DEFAULT_RESCAN_INTERVAL_MS = 2_000;

    private final Supplier<List<CardTerminal>> readerSource;
    private final Set<String> excludedReaderNames;
    private final Map<String, CardSlot> slotsByReaderName = new LinkedHashMap<>();
    private final ScheduledExecutorService scanner;
    private int nextIndex = 1;

    public PcscCardSlotBackend() {
        this(Set.of());
    }

    /**
     * @param excludedReaderNames readers that must never become a card slot — above all the reader
     *        holding the terminal's own gSMC-KT, whose card backs the SICCT TLS identity. Binding it
     *        as a card slot lets card discovery transmit to that card concurrently with TLS signing,
     *        corrupting the TLS session (the Konnektor sees {@code internal_error} and the connection
     *        drops mid-operation).
     */
    public PcscCardSlotBackend(Set<String> excludedReaderNames) {
        this(defaultReaderSource(), DEFAULT_RESCAN_INTERVAL_MS, excludedReaderNames);
    }

    /**
     * @param readerSource      supplies the currently connected readers on each scan
     * @param rescanIntervalMs  re-enumeration period; {@code <= 0} disables the background scan
     */
    PcscCardSlotBackend(Supplier<List<CardTerminal>> readerSource, long rescanIntervalMs) {
        this(readerSource, rescanIntervalMs, Set.of());
    }

    PcscCardSlotBackend(Supplier<List<CardTerminal>> readerSource, long rescanIntervalMs,
            Set<String> excludedReaderNames) {
        this.readerSource = readerSource;
        this.excludedReaderNames = Set.copyOf(excludedReaderNames);
        rescan();
        if (slots().isEmpty()) {
            log.warn("No PC/SC readers connected yet; will keep scanning for newly connected readers");
        }
        if (rescanIntervalMs > 0) {
            scanner = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "pcsc-reader-scan");
                t.setDaemon(true);
                return t;
            });
            scanner.scheduleWithFixedDelay(this::rescanQuietly,
                    rescanIntervalMs, rescanIntervalMs, TimeUnit.MILLISECONDS);
        } else {
            scanner = null;
        }
    }

    /** Re-enumerate readers now (test hook for the background scan). */
    synchronized void rescanNow() {
        rescan();
    }

    /** Bind any newly connected readers to fresh slots. Existing slots are left untouched. */
    private synchronized void rescan() {
        for (CardTerminal terminal : readerSource.get()) {
            String name = terminal.getName();
            if (excludedReaderNames.contains(name)) {
                continue; // never bind the gSMC-KT's own reader as a card slot (see constructor)
            }
            if (!slotsByReaderName.containsKey(name)) {
                int index = nextIndex++;
                slotsByReaderName.put(name, new PcscCardSlot(index, terminal));
                log.info("Bound slot {} to PC/SC reader '{}'", index, name);
            }
        }
    }

    private void rescanQuietly() {
        try {
            rescan();
        } catch (Exception e) {
            log.debug("PC/SC reader rescan failed", e);
        }
    }

    @Override
    public synchronized List<CardSlot> slots() {
        return new ArrayList<>(slotsByReaderName.values());
    }

    @Override
    public void close() {
        if (scanner != null) {
            scanner.shutdownNow();
        }
    }

    private static Supplier<List<CardTerminal>> defaultReaderSource() {
        return () -> {
            try {
                return TerminalFactory.getDefault().terminals().list();
            } catch (Exception e) {
                log.debug("Could not enumerate PC/SC readers", e);
                return List.of();
            }
        };
    }
}
