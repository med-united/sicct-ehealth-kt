package de.servicehealtherx.ehealthkt.sicct;

import java.util.HashMap;
import java.util.Map;

/**
 * Status of an ICC contact unit (card slot) as reported via SICCT GET STATUS.
 * Values per SICCT-Spezifikation V1.2.3.
 */
public enum IccStatus {
    /** No card present in the addressed contact unit (slot). */
    CC_ABSENT((byte) 0x00),
    /** A card is present but not moved into position for use; not powered. */
    CC_PRESENT((byte) 0x01),
    /** A card is in position for use but not powered. */
    CC_SWALLOWED((byte) 0x03),
    /** A card is in position for use and powered. */
    CC_POWERED((byte) 0x05),
    /** Card has been reset and is awaiting PTS negotiation. */
    CC_NEGOTIABLE((byte) 0x0D),
    /** Card has been reset and specific communication protocols have been established. */
    CC_SPECIFIC((byte) 0x15),
    /** The card terminal is unaware of the current slot state. */
    CC_UNKNOWN((byte) 0x80);

    private static final Map<Byte, IccStatus> BY_BYTE = new HashMap<>();

    static {
        for (IccStatus s : values()) {
            BY_BYTE.put(s.value, s);
        }
    }

    private final byte value;

    IccStatus(byte value) {
        this.value = value;
    }

    public static IccStatus from(byte b) {
        return BY_BYTE.get(b);
    }

    public byte value() {
        return value;
    }
}
