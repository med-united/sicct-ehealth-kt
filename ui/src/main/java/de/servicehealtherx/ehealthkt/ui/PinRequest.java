package de.servicehealtherx.ehealthkt.ui;

/**
 * Parameters for a PIN entry prompt on the terminal's own user interface (used whenever the PIN is
 * not captured by a card reader's PIN pad, including the Remote-PIN procedure). Lengths are in digits.
 *
 * @param prompt         the display message to show (e.g. the text the Konnektor sent)
 * @param slot           the addressed card slot
 * @param pinReference   P2 of the chipcard command the PIN is inserted into
 * @param minLength      minimum number of digits
 * @param maxLength      maximum number of digits
 * @param timeoutSeconds how long the caller waits for the entry; 0 = use the UI's own default
 */
public record PinRequest(String prompt, int slot, byte pinReference, int minLength, int maxLength,
                         int timeoutSeconds) {

    public PinRequest(String prompt, int slot, byte pinReference, int minLength, int maxLength) {
        this(prompt, slot, pinReference, minLength, maxLength, 0);
    }

    public static PinRequest forSlot(int slot, byte pinReference) {
        return new PinRequest("Enter PIN", slot, pinReference, 4, 8);
    }
}
