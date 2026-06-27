package de.servicehealtherx.ehealthkt.app.jmx;

import de.servicehealtherx.ehealthkt.ui.PinRequest;
import de.servicehealtherx.ehealthkt.ui.TerminalUi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A {@link TerminalUi} that routes pairing confirmations and PIN entry to the JMX management
 * interface instead of answering them locally.
 *
 * <p>When a SICCT command needs a pairing confirmation or a PIN, the calling (Netty) thread parks
 * until a JMX client answers via {@link EhealthKtManagement#confirmPairing()} /
 * {@link EhealthKtManagement#enterPin(String)} — or a timeout elapses, in which case the request
 * fails safe: confirmations are denied and PIN entry is cancelled. Display output is delegated to
 * the wrapped UI (e.g. the headless logger or the JavaFX display).
 *
 * <p>At most one confirmation and one PIN entry can be outstanding at a time; a second concurrent
 * request of the same kind is rejected immediately.
 */
public class JmxTerminalUi implements TerminalUi {

    private static final Logger log = LoggerFactory.getLogger(JmxTerminalUi.class);

    /** A pending confirm/PIN request awaiting a JMX answer. */
    private record Pending<T>(String line1, String line2, CompletableFuture<T> future) {
        String prompt() {
            return (line1 + " " + line2).trim();
        }
    }

    private final TerminalUi display;
    private final long timeoutMillis;
    private final AtomicReference<Pending<Boolean>> pendingConfirm = new AtomicReference<>();
    private final AtomicReference<Pending<char[]>> pendingPin = new AtomicReference<>();

    public JmxTerminalUi(TerminalUi display, long timeoutMillis) {
        this.display = display;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public void display(String line1, String line2) {
        display.display(line1, line2);
    }

    @Override
    public boolean confirm(String line1, String line2) {
        Pending<Boolean> pending = new Pending<>(line1, line2, new CompletableFuture<>());
        if (!pendingConfirm.compareAndSet(null, pending)) {
            log.warn("Confirmation '{} | {}' rejected: another confirmation is already pending", line1, line2);
            return false;
        }
        display.display(line1, line2);
        log.info("Awaiting JMX confirmation: {} | {}", line1, line2);
        try {
            return pending.future().get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            log.warn("Confirmation '{} | {}' timed out after {} ms; denying", line1, line2, timeoutMillis);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            log.warn("Confirmation '{} | {}' failed; denying", line1, line2, e);
            return false;
        } finally {
            pendingConfirm.compareAndSet(pending, null);
        }
    }

    @Override
    public char[] requestPin(PinRequest request) {
        String line1 = request.prompt();
        String line2 = "slot " + request.slot();
        Pending<char[]> pending = new Pending<>(line1, line2, new CompletableFuture<>());
        if (!pendingPin.compareAndSet(null, pending)) {
            log.warn("PIN request for slot {} rejected: another PIN entry is already pending", request.slot());
            return null;
        }
        display.display(line1, "Enter PIN via JMX");
        log.info("Awaiting JMX PIN entry for slot {} (ref 0x{})", request.slot(),
                Integer.toHexString(request.pinReference() & 0xFF));
        try {
            return pending.future().get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            log.warn("PIN entry for slot {} timed out after {} ms; cancelling", request.slot(), timeoutMillis);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            log.warn("PIN entry for slot {} failed; cancelling", request.slot(), e);
            return null;
        } finally {
            pendingPin.compareAndSet(pending, null);
        }
    }

    // --- JMX-facing API (called from JMX/RMI threads) ---

    /** Whether a pairing confirmation is currently awaiting an answer. */
    public boolean isConfirmPending() {
        return pendingConfirm.get() != null;
    }

    /** The prompt of the pending confirmation, or "" if none. */
    public String confirmPrompt() {
        Pending<Boolean> p = pendingConfirm.get();
        return p == null ? "" : p.prompt();
    }

    /** Whether a PIN entry is currently awaiting an answer. */
    public boolean isPinPending() {
        return pendingPin.get() != null;
    }

    /** The prompt of the pending PIN entry, or "" if none. */
    public String pinPrompt() {
        Pending<char[]> p = pendingPin.get();
        return p == null ? "" : p.prompt();
    }

    /** Answer the pending confirmation. Returns {@code false} if nothing was awaiting confirmation. */
    public boolean resolveConfirm(boolean accept) {
        Pending<Boolean> p = pendingConfirm.get();
        return p != null && p.future().complete(accept);
    }

    /** Answer the pending PIN entry. {@code pin} may be {@code null} to cancel. Returns {@code false}
     *  if no PIN was being requested. */
    public boolean resolvePin(char[] pin) {
        Pending<char[]> p = pendingPin.get();
        return p != null && p.future().complete(pin);
    }

    @Override
    public void close() {
        display.close();
    }
}
