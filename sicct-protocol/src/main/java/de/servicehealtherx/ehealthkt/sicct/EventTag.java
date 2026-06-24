package de.servicehealtherx.ehealthkt.sicct;

import java.util.HashMap;
import java.util.Map;

/**
 * Tags for SICCT event messages ({@link MessageType#EVENT}).
 */
public enum EventTag {
    KEEP_ALIVE((byte) 0x80, "Keep Alive"),
    TERMINAL_SIGN_OFF((byte) 0x81, "Terminal Sign Off"),
    FU_ADDED((byte) 0x82, "FU Added"),
    FU_REMOVED((byte) 0x83, "FU Removed"),
    CARD_INSERTED((byte) 0x84, "Card Inserted"),
    CARD_REMOVED((byte) 0x85, "Card Removed"),
    PROTOCOL_ERROR((byte) 0x86, "Protocol Error"),
    KEYBOARD_EVENT((byte) 0x87, "Keyboard Event");

    private static final Map<Byte, EventTag> BY_BYTE = new HashMap<>();

    static {
        for (EventTag t : values()) {
            BY_BYTE.put(t.value, t);
        }
    }

    private final byte value;
    private final String description;

    EventTag(byte value, String description) {
        this.value = value;
        this.description = description;
    }

    public static EventTag from(byte b) {
        return BY_BYTE.get(b);
    }

    public byte value() {
        return value;
    }

    public String description() {
        return description;
    }
}
