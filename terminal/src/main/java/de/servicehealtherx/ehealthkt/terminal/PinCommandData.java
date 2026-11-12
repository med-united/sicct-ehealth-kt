package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.sicct.StatusWord;
import de.servicehealtherx.ehealthkt.sicct.Tlv;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The parsed command data field of SICCT PERFORM VERIFICATION (INS 18) and SICCT MODIFY
 * VERIFICATION DATA (INS 1E): the display messages, the waiting times and the Command-To-Perform
 * Data Object (CMD DO, SICCT 5.5.10.23) — the chipcard APDU template into which the terminal
 * inserts the PIN(s) entered by the user.
 *
 * <p>The terminal never interprets the chipcard command beyond checking its INS byte. That is what
 * makes the <b>Remote-PIN</b> procedure (gemSpec_Kon TIP1-A_5012) work without any special casing:
 * the Konnektor addresses the terminal's gSMC-KT slot with a {@code PSO ENCIPHER} template, the
 * terminal inserts the PIN block, the gSMC-KT enciphers it with the trusted-channel session key and
 * the cryptogram goes back to the Konnektor, which forwards it to the HBA/SMC-B in another terminal.
 */
final class PinCommandData {

    private static final int TAG_APPLICATION_LABEL = 0x50;
    private static final int TAG_COMMAND_TO_PERFORM = 0x52;
    private static final int TAG_WAITING_TIME = 0x80;
    private static final int TAG_CHARACTER_SET = 0x85;
    private static final int TAG_MESSAGE_TO_BE_DISPLAYED = 0xA0;
    private static final int TAG_OCTET_STRING = 0x04;

    /** Display-message separator between the message and the PIN prompt (SICCT 5.6.1). */
    private static final int SEPARATOR_PIN_PROMPT = 0x0F;
    /** Display-message soft line break; filtered out, not counted as a character (SICCT 5.6.1). */
    private static final int SEPARATOR_SOFT_BREAK = 0x0B;

    private static final String DEFAULT_PIN_PROMPT = "INPUT: ";

    /** ISO 9564-1 bounds for a PIN. */
    static final int MIN_PIN_LENGTH = 4;
    static final int MAX_PIN_LENGTH = 12;

    /** PIN coding selected by bits b2..b1 of the CMD DO control byte. */
    enum PinFormat {BCD, ASCII, FORMAT_2}

    /** One display message: the text and the PIN prompt shown in front of the entry line. */
    record DisplayMessage(String text, String prompt) {
    }

    /** Signals an invalid command data field; carries the status word to answer with. */
    static final class InvalidPinCommandException extends RuntimeException {
        private final transient StatusWord statusWord;

        InvalidPinCommandException(StatusWord statusWord, String message) {
            super(message);
            this.statusWord = statusWord;
        }

        StatusWord statusWord() {
            return statusWord;
        }
    }

    private final List<DisplayMessage> messages;
    private final List<Integer> waitingTimes;
    private final int controlByte;
    private final int firstInsertionPosition;
    private final int secondInsertionPosition;
    private final byte[] apduTemplate;
    private final boolean modify;

    private PinCommandData(List<DisplayMessage> messages, List<Integer> waitingTimes, int controlByte,
                           int firstInsertionPosition, int secondInsertionPosition, byte[] apduTemplate,
                           boolean modify) {
        this.messages = messages;
        this.waitingTimes = waitingTimes;
        this.controlByte = controlByte;
        this.firstInsertionPosition = firstInsertionPosition;
        this.secondInsertionPosition = secondInsertionPosition;
        this.apduTemplate = apduTemplate;
        this.modify = modify;
    }

    /**
     * Parse the command data field.
     *
     * @param data   the APDU data field (concatenated data objects)
     * @param modify {@code true} for MODIFY VERIFICATION DATA (CMD DO carries two insertion positions)
     * @throws InvalidPinCommandException if the data objects are missing, duplicated or malformed
     */
    static PinCommandData parse(byte[] data, boolean modify) {
        if (data == null || data.length == 0) {
            throw new InvalidPinCommandException(StatusWord.WRONG_LENGTH, "no command data");
        }
        List<Tlv> objects;
        try {
            objects = Tlv.parseList(data);
        } catch (RuntimeException e) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "malformed data objects");
        }
        List<DisplayMessage> messages = new ArrayList<>();
        List<Integer> waitingTimes = new ArrayList<>();
        Tlv command = null;
        for (Tlv object : objects) {
            switch (object.tag()) {
                case TAG_APPLICATION_LABEL -> messages.add(decodeMessage(object.value(), 0));
                case TAG_MESSAGE_TO_BE_DISPLAYED -> messages.add(decodeSmtbd(object.value()));
                case TAG_WAITING_TIME -> {
                    if (object.value().length != 1) {
                        throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "invalid WT DO");
                    }
                    waitingTimes.add(object.value()[0] & 0xFF);
                }
                case TAG_COMMAND_TO_PERFORM -> {
                    if (command != null) {
                        throw new InvalidPinCommandException(StatusWord.TOO_MANY_DATA_OBJECTS, "two CMD DOs");
                    }
                    command = object;
                }
                default -> throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD,
                        "unsupported data object " + Integer.toHexString(object.tag()));
            }
        }
        if (messages.size() > 8 || waitingTimes.size() > 2) {
            throw new InvalidPinCommandException(StatusWord.TOO_MANY_DATA_OBJECTS, "too many data objects");
        }
        if (command == null) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "missing CMD DO");
        }
        byte[] value = command.value();
        int headerLength = modify ? 3 : 2;
        if (value.length < headerLength + 4) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "CMD DO too short");
        }
        int controlByte = value[0] & 0xFF;
        if ((controlByte & 0x03) == 0x03) {
            // b2..b1 = 11 is RFU; this also rejects 'FF' (biometric identification, no sensor here).
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "unsupported PIN format");
        }
        int first = value[1] & 0xFF;
        int second = modify ? value[2] & 0xFF : 0;
        byte[] apdu = Arrays.copyOfRange(value, headerLength, value.length);
        requireAllowedInstruction(apdu);
        if (first == 0 && !modify) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "insertion position 0");
        }
        return new PinCommandData(List.copyOf(messages), List.copyOf(waitingTimes), controlByte, first, second,
                apdu, modify);
    }

    /**
     * The text of the first display message (APPL DO or SMTBD DO) in a command data field, e.g. of
     * SICCT OUTPUT; a data field without data objects is taken as plain text. Never throws.
     */
    static String firstDisplayText(byte[] data) {
        try {
            for (Tlv object : Tlv.parseList(data)) {
                if (object.tag() == TAG_APPLICATION_LABEL) {
                    return decodeMessage(object.value(), 0).text();
                }
                if (object.tag() == TAG_MESSAGE_TO_BE_DISPLAYED) {
                    return decodeSmtbd(object.value()).text();
                }
            }
        } catch (RuntimeException e) {
            // not TLV-coded (or too long for a PIN dialog): fall through to the raw text
        }
        StringBuilder text = new StringBuilder();
        for (byte b : data) {
            text.append(decodeCharacter(b & 0xFF, 0));
        }
        return text.toString().trim();
    }

    /** Only the chipcard instructions listed in SICCT 5.5.10.23 may be performed with a PIN inserted. */
    private static void requireAllowedInstruction(byte[] apdu) {
        int ins = apdu[1] & 0xFF;
        boolean allowed = switch (ins) {
            case 0x20, 0x24, 0x26, 0x28, 0x2C -> true;
            // PERFORM SECURITY OPERATION: only the ENCIPHER variants (P1 82/84/86, P2 80).
            case 0x2A -> {
                int p1 = apdu[2] & 0xFF;
                yield (p1 == 0x82 || p1 == 0x84 || p1 == 0x86) && (apdu[3] & 0xFF) == 0x80;
            }
            default -> false;
        };
        if (!allowed) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD,
                    "chipcard instruction " + Integer.toHexString(ins) + " not allowed in CMD DO");
        }
    }

    private static DisplayMessage decodeSmtbd(byte[] value) {
        List<Tlv> children;
        try {
            children = Tlv.parseList(value);
        } catch (RuntimeException e) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "malformed SMTBD DO");
        }
        Tlv characterSet = Tlv.find(children, TAG_CHARACTER_SET);
        Tlv text = Tlv.find(children, TAG_OCTET_STRING);
        if (text == null) {
            text = Tlv.find(children, TAG_APPLICATION_LABEL);
        }
        int characterSetIndex = characterSet == null || characterSet.value().length == 0
                ? 0 : characterSet.value()[0] & 0xFF;
        return decodeMessage(text == null ? new byte[0] : text.value(), characterSetIndex);
    }

    /** Split {@code message '0F' prompt}, drop soft breaks and map the bytes to displayable text. */
    private static DisplayMessage decodeMessage(byte[] value, int characterSetIndex) {
        StringBuilder text = new StringBuilder();
        StringBuilder prompt = null;
        for (byte b : value) {
            int c = b & 0xFF;
            if (c == SEPARATOR_SOFT_BREAK) {
                continue;
            }
            if (c == SEPARATOR_PIN_PROMPT) {
                if (prompt == null) {
                    prompt = new StringBuilder();
                }
                continue;
            }
            (prompt == null ? text : prompt).append(decodeCharacter(c, characterSetIndex));
        }
        if (text.length() > 48 || (prompt != null && prompt.length() > 10)) {
            // SICCT 5.6.1: a message that is too long must be suppressed and answered with 6A80.
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "display message too long");
        }
        return new DisplayMessage(text.toString(), prompt == null ? DEFAULT_PIN_PROMPT : prompt.toString());
    }

    /** Character set 00 is ISO 646-DE (DIN 66003), 01 is ISO 8859-1; anything unsupported is a space. */
    private static char decodeCharacter(int c, int characterSetIndex) {
        if (c < 0x20) {
            return ' ';
        }
        if (characterSetIndex == 1) {
            return (char) c;
        }
        if (c > 0x7E) {
            return ' ';
        }
        return switch (c) {
            case 0x40 -> '§';
            case 0x5B -> 'Ä';
            case 0x5C -> 'Ö';
            case 0x5D -> 'Ü';
            case 0x7B -> 'ä';
            case 0x7C -> 'ö';
            case 0x7D -> 'ü';
            case 0x7E -> 'ß';
            default -> (char) c;
        };
    }

    /** The n-th display message (0-based) or a default when the caller did not override it. */
    DisplayMessage message(int index, String defaultText) {
        if (index < messages.size() && !messages.get(index).text().isEmpty()) {
            return messages.get(index);
        }
        return new DisplayMessage(defaultText, DEFAULT_PIN_PROMPT);
    }

    /** Waiting time in seconds until the PIN must have been entered; 0 if the caller gave none. */
    int waitingTimeSeconds() {
        return waitingTimes.isEmpty() ? 0 : waitingTimes.get(0);
    }

    PinFormat format() {
        return switch (controlByte & 0x03) {
            case 0x00 -> PinFormat.BCD;
            case 0x01 -> PinFormat.ASCII;
            default -> PinFormat.FORMAT_2;
        };
    }

    /** Whether b4..b3 = 01: for MODIFY, b8..b5 then give the minimum length of the new PIN only. */
    private boolean lengthAppliesToNewPinOnly() {
        return modify && (controlByte & 0x0C) == 0x04;
    }

    private int codedLength() {
        return (controlByte >> 4) & 0x0F;
    }

    /** Minimum number of digits for the PIN to verify (the old PIN of a MODIFY). */
    int minLength() {
        int length = codedLength();
        return length == 0 || lengthAppliesToNewPinOnly() ? MIN_PIN_LENGTH : clamp(length);
    }

    /** Maximum number of digits for the PIN to verify (the old PIN of a MODIFY). */
    int maxLength() {
        int length = codedLength();
        return length == 0 || lengthAppliesToNewPinOnly() ? MAX_PIN_LENGTH : clamp(length);
    }

    /** Minimum number of digits for the new PIN of a MODIFY. */
    int newPinMinLength() {
        int length = codedLength();
        return length == 0 ? MIN_PIN_LENGTH : clamp(length);
    }

    /** Maximum number of digits for the new PIN of a MODIFY. */
    int newPinMaxLength() {
        int length = codedLength();
        return length == 0 || lengthAppliesToNewPinOnly() ? MAX_PIN_LENGTH : clamp(length);
    }

    private static int clamp(int length) {
        return Math.max(MIN_PIN_LENGTH, Math.min(MAX_PIN_LENGTH, length));
    }

    /** MODIFY "Null-PIN": first insertion position 00 means only the new PIN is entered. */
    boolean skipsFirstPin() {
        return modify && firstInsertionPosition == 0;
    }

    /** The chipcard instruction of the command to perform (e.g. 20 VERIFY, 2A PSO). */
    byte instruction() {
        return apduTemplate[1];
    }

    /** P2 of the command to perform — for VERIFY and friends the PIN reference. */
    byte p2() {
        return apduTemplate[3];
    }

    /**
     * Whether the command to perform is exactly a plain VERIFY with a format-2 PIN block, i.e. what a
     * PC/SC reader's own PIN pad can execute via {@code FEATURE_VERIFY_PIN_DIRECT}.
     */
    boolean isPlainFormat2Verify() {
        return !modify && format() == PinFormat.FORMAT_2 && apduTemplate[0] == 0x00
                && apduTemplate[1] == 0x20 && apduTemplate[2] == 0x00 && firstInsertionPosition == 6
                && apduTemplate.length <= 13;
    }

    /** Build the chipcard APDU for PERFORM VERIFICATION with the entered PIN inserted. */
    byte[] buildApdu(char[] pin) {
        return insert(apduTemplate, firstInsertionPosition, pin);
    }

    /**
     * Build the chipcard APDU for MODIFY VERIFICATION DATA. {@code oldPin} is ignored (may be
     * {@code null}) when {@link #skipsFirstPin()}.
     */
    byte[] buildApdu(char[] oldPin, char[] newPin) {
        byte[] apdu = apduTemplate;
        if (!skipsFirstPin()) {
            apdu = insert(apdu, firstInsertionPosition, oldPin);
        }
        byte[] result = insert(apdu, secondInsertionPosition, newPin);
        if (apdu != apduTemplate) {
            Arrays.fill(apdu, (byte) 0);
        }
        return result;
    }

    /**
     * Insert {@code pin} into {@code apdu} at the 1-based {@code position} (counted from CLA). Supports
     * both template forms of SICCT 5.5.10.23: a bare 4-byte header (the PIN becomes the data field)
     * and a header with Lc and a pre-formatted data field (the PIN overwrites the padding; if it
     * reaches beyond the data field the field grows and Lc is adjusted, a trailing Le is kept).
     */
    private byte[] insert(byte[] apdu, int position, char[] pin) {
        PinFormat format = format();
        int encodedLength = switch (format) {
            case FORMAT_2 -> 8;
            case ASCII -> pin.length;
            case BCD -> (pin.length + 1) / 2;
        };
        int offset = position - 1;
        if (offset < 5) {
            throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD, "insertion position < 6");
        }
        byte[] result;
        if (apdu.length == 4) {
            if (offset != 5) {
                throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD,
                        "insertion position beyond header-only command");
            }
            result = new byte[5 + encodedLength];
            System.arraycopy(apdu, 0, result, 0, 4);
            Arrays.fill(result, 5, result.length, (byte) 0xFF);
        } else {
            int dataEnd = 5 + (apdu[4] & 0xFF);
            if (dataEnd > apdu.length || offset > dataEnd) {
                throw new InvalidPinCommandException(StatusWord.INCORRECT_DATA_FIELD,
                        "insertion position outside the command data field");
            }
            int growth = Math.max(0, offset + encodedLength - dataEnd);
            if (dataEnd - 5 + growth > 255) {
                throw new InvalidPinCommandException(StatusWord.WRONG_LENGTH, "command data too long");
            }
            result = new byte[apdu.length + growth];
            System.arraycopy(apdu, 0, result, 0, dataEnd);
            Arrays.fill(result, dataEnd, dataEnd + growth, (byte) 0xFF);
            System.arraycopy(apdu, dataEnd, result, dataEnd + growth, apdu.length - dataEnd);
        }
        switch (format) {
            case ASCII -> {
                for (int i = 0; i < pin.length; i++) {
                    result[offset + i] = (byte) pin[i];
                }
            }
            case BCD -> writeDigits(result, offset, 0, pin);
            case FORMAT_2 -> {
                // ISO 9564-1 format 2: control nibble '2', length nibble, digits, filler 'F'.
                Arrays.fill(result, offset, offset + 8, (byte) 0xFF);
                result[offset] = (byte) (0x20 | pin.length);
                writeDigits(result, offset, 2, pin);
            }
        }
        if (result.length > 4) {
            int trailing = apdu.length == 4 ? 0 : apdu.length - (5 + (apdu[4] & 0xFF));
            result[4] = (byte) (result.length - 5 - trailing);
        }
        return result;
    }

    /** Write the PIN digits as BCD nibbles, starting {@code nibbleOffset} nibbles after {@code offset}. */
    private static void writeDigits(byte[] target, int offset, int nibbleOffset, char[] pin) {
        for (int i = 0; i < pin.length; i++) {
            int nibble = nibbleOffset + i;
            int index = offset + nibble / 2;
            int digit = pin[i] - '0';
            if (nibble % 2 == 0) {
                target[index] = (byte) ((digit << 4) | (target[index] & 0x0F));
            } else {
                target[index] = (byte) ((target[index] & 0xF0) | digit);
            }
        }
    }
}
