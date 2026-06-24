package de.servicehealtherx.ehealthkt.sicct;

/**
 * ISO 7816-4 / SICCT response status words (SW1 SW2) used by the terminal.
 */
public enum StatusWord {
    SUCCESS(0x9000, "Command successfully executed"),
    COMMAND_NOT_ALLOWED(0x6900, "Command not allowed (no information given)"),
    COMMAND_NOT_ALLOWED_INVALID_CLIENT(0x6901, "Command not allowed (invalid client / no pairing)"),
    SECURITY_CONDITION_NOT_SATISFIED(0x6982, "Security condition not satisfied"),
    AUTHENTICATION_METHOD_BLOCKED(0x6983, "Authentication method blocked"),
    CONDITIONS_NOT_SATISFIED(0x6985, "Conditions of use not satisfied"),
    REFERENCED_DATA_NOT_FOUND(0x6A88, "Referenced data not found"),
    WRONG_PARAMETERS_P1P2(0x6A86, "Wrong parameters P1-P2"),
    INCORRECT_DATA_FIELD(0x6A80, "Parameters in data field incorrect"),
    INSTRUCTION_NOT_SUPPORTED(0x6D00, "Instruction not supported / wrong instruction"),
    CLASS_NOT_SUPPORTED(0x6E00, "Class not supported"),
    COMMAND_TIMEOUT(0x6401, "Command timeout"),
    NO_INFORMATION(0x6400, "No information given (state unchanged)"),
    SICCT_CONTROL_RESPONSE(0x6200, "SICCT control response"),
    WRONG_LENGTH(0x6700, "Wrong length");

    private final int code;
    private final String text;

    StatusWord(int code, String text) {
        this.code = code;
        this.text = text;
    }

    public int code() {
        return code;
    }

    public String text() {
        return text;
    }

    /** The two trailer bytes SW1 SW2. */
    public byte[] toBytes() {
        return new byte[]{(byte) ((code >> 8) & 0xff), (byte) (code & 0xff)};
    }

    public short toShort() {
        return (short) code;
    }
}
