package de.servicehealtherx.ehealthkt.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;

/**
 * A non-graphical {@link TerminalUi} for server mode, tests and CI. Display lines are logged;
 * PIN entry and confirmations are answered by configurable suppliers (scripted responses).
 */
public class HeadlessUi implements TerminalUi {

    private static final Logger log = LoggerFactory.getLogger(HeadlessUi.class);

    private final Supplier<char[]> pinSupplier;
    private final boolean autoConfirm;

    private volatile String line1 = "";
    private volatile String line2 = "";

    public HeadlessUi() {
        this(() -> null, true);
    }

    public HeadlessUi(Supplier<char[]> pinSupplier, boolean autoConfirm) {
        this.pinSupplier = pinSupplier;
        this.autoConfirm = autoConfirm;
    }

    /** A headless UI that always returns the given PIN and auto-confirms. */
    public static HeadlessUi withPin(String pin) {
        return new HeadlessUi(() -> pin == null ? null : pin.toCharArray(), true);
    }

    @Override
    public void display(String line1, String line2) {
        this.line1 = line1 == null ? "" : line1;
        this.line2 = line2 == null ? "" : line2;
        log.info("[display] {} | {}", this.line1, this.line2);
    }

    @Override
    public char[] requestPin(PinRequest request) {
        log.info("[pin] requested for slot {} (ref 0x{})", request.slot(),
                Integer.toHexString(request.pinReference() & 0xFF));
        return pinSupplier.get();
    }

    @Override
    public boolean confirm(String line1, String line2) {
        log.info("[confirm] {} | {} -> {}", line1, line2, autoConfirm);
        return autoConfirm;
    }

    public String line1() {
        return line1;
    }

    public String line2() {
        return line2;
    }
}
