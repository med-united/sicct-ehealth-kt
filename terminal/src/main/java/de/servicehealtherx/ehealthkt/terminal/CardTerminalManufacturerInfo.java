package de.servicehealtherx.ehealthkt.terminal;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Builds the SICCT <b>CardTerminal Manufacturer Data Object</b> (CTM DO, tag {@code 0x46};
 * SICCT 5.5.10.6) returned in response to GET STATUS with {@code P2='46'}. It carries the invariant
 * pre-issuing data of the terminal and embeds the gematik-mandated <b>Discretionary Data Data
 * Object</b> (DD DO, tag {@code 0xD7}; gemSpec_KT {@code DO_KT_0001} / {@code DO_KT_0002},
 * TIP1-A_3131 / TIP1-A_3118), which holds the version fields.
 *
 * <pre>
 * CTM DO  46 &lt;len&gt;
 *   CTM   5  "DESRX"   country code (ISO 3166) + gematik manufacturer acronym
 *   CTT   5  "0130 "   SICCT specification version (this terminal: SICCT 1.3.0)
 *   CTSV  5  "0100 "   cardterminal software version
 *   DD DO d7 &lt;len&gt;
 *     VER   9  EHEALTH interface version   [major][minor][revision], each space-left-padded to 3
 *     PT    2  "KT"    product type
 *     PTV   9  producttype version
 *     MODN  8  model name (space-left-padded)
 *     FWV   9  firmware version
 *     HWV   9  hardware version
 *     FWG   5  firmware group version
 * </pre>
 *
 * Each {@code [major][minor][revision]} version triplet is a 9-byte ASCII string of three decimal
 * fields, each left-padded with spaces ({@code '20'}) to 3 characters (gemSpec_KT DO_KT_0002, e.g.
 * version {@code 2.61.242} -&gt; {@code "  2 61242"}).
 */
public final class CardTerminalManufacturerInfo {

    /** GET STATUS qualifier (P2) requesting the CardTerminal Manufacturer Data Object. */
    public static final byte P2_CARD_TERMINAL_MANUFACTURER = 0x46;

    private static final int TAG_CTM_DO = 0x46;
    private static final int TAG_DD_DO = 0xD7;

    // CTM: 2-byte ISO 3166 country code ("DE") + 3-byte gematik-assigned manufacturer acronym.
    private static final String MANUFACTURER = "DESRX";
    // CTT: SICCT specification version implemented by this terminal (SICCT 1.3.0).
    private static final String SICCT_VERSION = "0130 ";
    // CTSV: cardterminal software version.
    private static final String SOFTWARE_VERSION = "0100 ";

    // Discretionary Data fields (gemSpec_KT DO_KT_0002).
    private static final int[] EHEALTH_INTERFACE_VERSION = {1, 0, 0};   // VER
    private static final String PRODUCT_TYPE = "KT";                    // PT
    private static final int[] PRODUCTTYPE_VERSION = {1, 5, 0};         // PTV
    private static final String MODEL_NAME = "EHKTSRX";                 // MODN (<= 8 bytes)
    private static final int[] FIRMWARE_VERSION = {1, 0, 0};            // FWV
    private static final int[] HARDWARE_VERSION = {1, 0, 0};            // HWV
    private static final String FIRMWARE_GROUP = "00017";              // FWG (5 bytes)

    private CardTerminalManufacturerInfo() {
    }

    /** The full CardTerminal Manufacturer Data Object: {@code 46 <len> <value>} (no SW trailer). */
    public static byte[] dataObject() {
        ByteArrayOutputStream value = new ByteArrayOutputStream();
        value.writeBytes(ascii(MANUFACTURER, 5));
        value.writeBytes(ascii(SICCT_VERSION, 5));
        value.writeBytes(ascii(SOFTWARE_VERSION, 5));
        value.writeBytes(discretionaryDataObject());
        return tlv(TAG_CTM_DO, value.toByteArray());
    }

    /** The Discretionary Data Data Object: {@code d7 <len> <version fields>}. */
    private static byte[] discretionaryDataObject() {
        ByteArrayOutputStream dd = new ByteArrayOutputStream();
        dd.writeBytes(version(EHEALTH_INTERFACE_VERSION)); // VER  (9)
        dd.writeBytes(ascii(PRODUCT_TYPE, 2));             // PT   (2)
        dd.writeBytes(version(PRODUCTTYPE_VERSION));        // PTV  (9)
        dd.writeBytes(ascii(MODEL_NAME, 8));               // MODN (8)
        dd.writeBytes(version(FIRMWARE_VERSION));           // FWV  (9)
        dd.writeBytes(version(HARDWARE_VERSION));           // HWV  (9)
        dd.writeBytes(ascii(FIRMWARE_GROUP, 5));           // FWG  (5)
        return tlv(TAG_DD_DO, dd.toByteArray());
    }

    /** Encode a {@code [major][minor][revision]} triplet as 9 ASCII bytes, each field width 3. */
    private static byte[] version(int[] majorMinorRevision) {
        StringBuilder sb = new StringBuilder(9);
        for (int field : majorMinorRevision) {
            String s = Integer.toString(field);
            sb.append(" ".repeat(3 - s.length())).append(s); // left-pad with space to width 3
        }
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** ASCII bytes of {@code s} truncated or left-padded with spaces to exactly {@code length}. */
    private static byte[] ascii(String s, int length) {
        byte[] out = new byte[length];
        byte[] src = s.getBytes(StandardCharsets.US_ASCII);
        int n = Math.min(src.length, length);
        // left-pad with spaces so the value is right-aligned in the fixed-width field
        java.util.Arrays.fill(out, (byte) ' ');
        System.arraycopy(src, 0, out, length - n, n);
        return out;
    }

    private static byte[] tlv(int tag, byte[] value) {
        byte[] out = new byte[2 + value.length];
        out[0] = (byte) tag;
        out[1] = (byte) value.length; // single-byte length: CTM DO <= 127, DD DO 51..110
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }
}
