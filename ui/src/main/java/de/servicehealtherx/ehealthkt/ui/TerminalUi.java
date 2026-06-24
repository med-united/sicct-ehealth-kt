package de.servicehealtherx.ehealthkt.ui;

/**
 * The terminal's user interface: a small text display (at least 2x16 characters per gemSpec_KT
 * TIP1-A_2950) and PIN/confirmation entry.
 *
 * <p>When the card reader provides a secure PIN pad, PIN entry happens on the reader and the UI
 * is only asked to display a hint via {@link #display}. When it does not, the terminal asks the
 * UI for the PIN via {@link #requestPin(PinRequest)} ("remote PIN" / host entry).
 */
public interface TerminalUi extends AutoCloseable {

    /** Show up to two lines of text on the terminal display. */
    void display(String line1, String line2);

    /** Clear the display to the idle screen. */
    default void clear() {
        display("", "");
    }

    /**
     * Prompt the user to enter a PIN on the host. Returns the entered digits, or {@code null}
     * if the user cancelled or timed out. The caller must zero the array after use.
     */
    char[] requestPin(PinRequest request);

    /** Ask the user to confirm an action (e.g. pairing). Returns true if confirmed. */
    boolean confirm(String line1, String line2);

    @Override
    default void close() {
    }
}
