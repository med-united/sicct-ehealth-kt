package de.servicehealtherx.ehealthkt.ui;

/**
 * Parameters for a host PIN entry prompt (used when the reader has no secure PIN pad,
 * i.e. "remote PIN"). Lengths are in digits.
 */
public record PinRequest(String prompt, int slot, byte pinReference, int minLength, int maxLength) {

    public static PinRequest forSlot(int slot, byte pinReference) {
        return new PinRequest("Enter PIN", slot, pinReference, 4, 8);
    }
}
