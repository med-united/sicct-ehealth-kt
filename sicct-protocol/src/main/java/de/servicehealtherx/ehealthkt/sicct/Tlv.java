package de.servicehealtherx.ehealthkt.sicct;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal BER-TLV data object: a tag, a length and a value. Supports one- and
 * two-byte tags and definite length encoding (short form and long form up to 3
 * length bytes). Sufficient for the SICCT data objects used by an eHealth-KT
 * (status data objects, pairing data objects, etc.).
 */
public final class Tlv {

    private final int tag;
    private final byte[] value;

    public Tlv(int tag, byte[] value) {
        this.tag = tag;
        this.value = value;
    }

    public int tag() {
        return tag;
    }

    public byte[] value() {
        return value;
    }

    /** Encode this TLV (tag + length + value). */
    public byte[] toBytes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // tag
        if (tag > 0xFF) {
            out.write((tag >> 8) & 0xFF);
        }
        out.write(tag & 0xFF);
        // length
        int len = value.length;
        if (len < 0x80) {
            out.write(len);
        } else if (len < 0x100) {
            out.write(0x81);
            out.write(len);
        } else if (len < 0x10000) {
            out.write(0x82);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        } else {
            out.write(0x83);
            out.write((len >> 16) & 0xFF);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }

    /** Parse a sequence of concatenated TLVs. */
    public static List<Tlv> parseList(byte[] data) {
        List<Tlv> result = new ArrayList<>();
        int pos = 0;
        while (pos < data.length) {
            int tag = data[pos++] & 0xFF;
            // two-byte tag if low 5 bits of first byte are all set
            if ((tag & 0x1F) == 0x1F) {
                tag = (tag << 8) | (data[pos++] & 0xFF);
            }
            int first = data[pos++] & 0xFF;
            int len;
            if (first < 0x80) {
                len = first;
            } else {
                int numBytes = first & 0x7F;
                len = 0;
                for (int i = 0; i < numBytes; i++) {
                    len = (len << 8) | (data[pos++] & 0xFF);
                }
            }
            byte[] value = new byte[len];
            System.arraycopy(data, pos, value, 0, len);
            pos += len;
            result.add(new Tlv(tag, value));
        }
        return result;
    }

    /** Find the first TLV with the given tag, or {@code null}. */
    public static Tlv find(List<Tlv> tlvs, int tag) {
        for (Tlv t : tlvs) {
            if (t.tag == tag) {
                return t;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return "Tlv[" + Integer.toHexString(tag) + " (" + value.length + ") " + Hex.toHex(value) + "]";
    }
}
