package de.servicehealtherx.ehealthkt.sicct;

/**
 * Hex / byte-array conversion helpers used across the SICCT protocol layer.
 * Ported and trimmed from the CardLink {@code HexConverter}; no external deps.
 */
public final class Hex {

    private static final char[] HEX_CODE = "0123456789ABCDEF".toCharArray();

    private Hex() {
    }

    public static byte[] toBytes(String hexString) {
        int len = hexString == null ? 0 : hexString.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("hex-string has to be even-length: " + hexString);
        }
        byte[] bytes = new byte[len / 2];
        int j = 0;
        for (int i = 0; i < bytes.length; i++) {
            int highNibble = hexCharToDec(hexString.charAt(j++));
            int lowNibble = hexCharToDec(hexString.charAt(j++));
            bytes[i] = (byte) ((highNibble << 4) | lowNibble);
        }
        return bytes;
    }

    private static int hexCharToDec(char c) {
        if ('0' <= c && c <= '9') return c - '0';
        if ('A' <= c && c <= 'F') return c - 'A' + 10;
        if ('a' <= c && c <= 'f') return c - 'a' + 10;
        throw new IllegalArgumentException("illegal hex character: " + c);
    }

    public static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int i = 0;
        for (byte b : bytes) {
            hexChars[i++] = HEX_CODE[Byte.toUnsignedInt(b) >> 4];
            hexChars[i++] = HEX_CODE[b & 0xf];
        }
        return new String(hexChars);
    }

    public static String toHex(byte b) {
        return new String(new char[]{HEX_CODE[Byte.toUnsignedInt(b) >> 4], HEX_CODE[b & 0xf]});
    }

    public static byte[] intTo4Bytes(int number) {
        return new byte[]{
                (byte) (number >>> 24),
                (byte) (number >>> 16),
                (byte) (number >>> 8),
                (byte) number
        };
    }

    public static int bytesToInt(byte[] b) {
        return (Byte.toUnsignedInt(b[0]) << 24)
                | (Byte.toUnsignedInt(b[1]) << 16)
                | (Byte.toUnsignedInt(b[2]) << 8)
                | Byte.toUnsignedInt(b[3]);
    }

    public static short bytesToShort(byte high, byte low) {
        return (short) ((Byte.toUnsignedInt(high) << 8) | Byte.toUnsignedInt(low));
    }

    public static byte[] shortTo2Bytes(short value) {
        return new byte[]{(byte) (value >> 8), (byte) value};
    }

    public static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) {
            len += a.length;
        }
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }
}
