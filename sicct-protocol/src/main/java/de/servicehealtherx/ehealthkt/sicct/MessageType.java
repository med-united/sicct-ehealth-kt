package de.servicehealtherx.ehealthkt.sicct;

import java.util.HashMap;
import java.util.Map;

/**
 * SICCT message type (first byte of the envelope).
 * <ul>
 *   <li>{@code 0x6B} C-Kommando (command)</li>
 *   <li>{@code 0x83} R-Kommando (response)</li>
 *   <li>{@code 0x50} Ereignisnachricht (event)</li>
 * </ul>
 */
public enum MessageType {
    COMMAND((byte) 0x6b),
    RESPONSE((byte) 0x83),
    EVENT((byte) 0x50);

    private static final Map<Byte, MessageType> BY_BYTE = new HashMap<>();

    static {
        for (MessageType t : values()) {
            BY_BYTE.put(t.value, t);
        }
    }

    private final byte value;

    MessageType(byte value) {
        this.value = value;
    }

    public static MessageType from(byte b) {
        return BY_BYTE.get(b);
    }

    public byte value() {
        return value;
    }
}
