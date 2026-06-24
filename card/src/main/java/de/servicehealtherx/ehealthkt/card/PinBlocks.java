package de.servicehealtherx.ehealthkt.card;

/**
 * PIN encoding helpers. The format-2 PIN block encoding and the PC/SC {@code PIN_VERIFY}
 * control structure are ported from the eHBA reference implementation
 * ({@code de.service.health.ehba.EHBACard}).
 */
public final class PinBlocks {

    private PinBlocks() {
    }

    /** Encode a numeric PIN as an 8-byte ISO format-2 PIN block. */
    public static byte[] encodeFormat2(String pin) {
        int[] intPin = new int[pin.length()];
        for (int i = 0; i < pin.length(); i++) {
            intPin[i] = pin.charAt(i) - '0';
        }
        byte[] format2 = new byte[8];
        format2[0] = (byte) ((0x02 << 4) | pin.length());
        for (int i = 0; i < intPin.length; i++) {
            if ((i + 2) % 2 == 0) {
                format2[1 + i / 2] += (byte) (intPin[i] << 4);
            } else {
                format2[1 + i / 2] += (byte) intPin[i];
            }
        }
        for (int i = intPin.length; i < 2 * 8 - 2; i++) {
            if (i % 2 == 0) {
                format2[1 + i / 2] += (byte) (0x0F << 4);
            } else {
                format2[1 + i / 2] += 0x0F;
            }
        }
        return format2;
    }

    /** Build a software VERIFY command APDU ({@code 00 20 00 P2} + format-2 block). */
    public static byte[] verifyApdu(byte pinReference, String pin) {
        byte[] block = encodeFormat2(pin);
        byte[] apdu = new byte[5 + block.length];
        apdu[0] = 0x00;
        apdu[1] = 0x20;
        apdu[2] = 0x00;
        apdu[3] = pinReference;
        apdu[4] = (byte) block.length;
        System.arraycopy(block, 0, apdu, 5, block.length);
        return apdu;
    }

    /** Build the CCID {@code PIN_VERIFY} control structure for FEATURE_VERIFY_PIN_DIRECT. */
    public static byte[] pinVerifyStructure(byte pinReference) {
        return new byte[]{
                0x00,        // bTimeOut
                0x00,        // bTimeOut2
                (byte) 0x89, // bmFormatString: BCD, system unit byte, left justify
                0x47,        // bmPINBlockString: 4-byte block, fill nibble 0xF
                0x04,        // bmPINLengthFormat: nibble
                0x08,        // wPINMaxExtraDigit lo: max 8
                0x04,        // wPINMaxExtraDigit hi: min 4
                0x02,        // bEntryValidationCondition: enter pressed
                0x00,        // bNumberMessage
                0x00,        // wLangId lo
                0x00,        // wLangId hi
                0x00,        // bMsgIndex
                0x00, 0x00, 0x00, // bTeoPrologue
                0x0D, 0x00, 0x00, 0x00, // ulDataLength = 13 byte APDU
                // APDU (13 bytes): VERIFY with placeholder PIN block
                0x00, 0x20, 0x00, pinReference, 0x08,
                0x20, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        };
    }
}
