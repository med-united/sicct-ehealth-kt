package de.servicehealtherx.ehealthkt.sicct;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * A SICCT message: a 10-byte envelope followed by a payload (a SICCT command APDU
 * or an ISO-7816 APDU). Ported from the CardLink {@code Message} class.
 *
 * <pre>
 * offset  size  field
 *   0       1   message type (6B command / 83 response / 50 event)
 *   1       2   source/destination address (slot), network byte order
 *   3       2   sequence number, network byte order
 *   5       1   RFU
 *   6       4   payload length (network byte order)
 *  10       n   payload (APDU)
 * </pre>
 */
public class SicctMessage {

    public static final int HEADER_LENGTH = 10;

    private static final Logger log = LoggerFactory.getLogger(SicctMessage.class);

    private byte[] raw;

    public SicctMessage(byte[] raw) {
        this.raw = raw;
    }

    /** Build a well-formed SICCT message from its parts. */
    public static SicctMessage of(MessageType type, short slot, short seq, byte[] payload) {
        byte[] raw = new byte[HEADER_LENGTH + payload.length];
        raw[0] = type.value();
        byte[] addr = Hex.shortTo2Bytes(slot);
        raw[1] = addr[0];
        raw[2] = addr[1];
        byte[] s = Hex.shortTo2Bytes(seq);
        raw[3] = s[0];
        raw[4] = s[1];
        raw[5] = 0x00;
        byte[] len = Hex.intTo4Bytes(payload.length);
        System.arraycopy(len, 0, raw, 6, 4);
        System.arraycopy(payload, 0, raw, HEADER_LENGTH, payload.length);
        return new SicctMessage(raw);
    }

    /** Build a response message addressed back from {@code slot} with the same sequence number. */
    public SicctMessage toResponse(byte[] payload) {
        return of(MessageType.RESPONSE, getSlot(), getSeqShort(), payload);
    }

    public byte[] getRaw() {
        return raw;
    }

    public void setRaw(byte[] raw) {
        this.raw = raw;
    }

    public byte getMessageType() {
        return raw[0];
    }

    public MessageType type() {
        return MessageType.from(raw[0]);
    }

    public short getSlot() {
        return Hex.bytesToShort(raw[1], raw[2]);
    }

    public short getSeqShort() {
        return Hex.bytesToShort(raw[3], raw[4]);
    }

    public byte[] getSeq() {
        if (raw == null || raw.length < 5) {
            return null;
        }
        return new byte[]{raw[3], raw[4]};
    }

    public int getLength() {
        return ByteBuffer.wrap(new byte[]{raw[6], raw[7], raw[8], raw[9]}).getInt();
    }

    public byte[] getBody() {
        return Arrays.copyOfRange(raw, HEADER_LENGTH, HEADER_LENGTH + getLength());
    }

    public byte getCla() {
        return getBody()[0];
    }

    public byte getIns() {
        return getBody()[1];
    }

    public byte getP1() {
        return getBody()[2];
    }

    public byte getP2() {
        return getBody()[3];
    }

    /**
     * The command data field (between Lc and Le) of the APDU in this message, handling both
     * short and extended length encoding. Returns an empty array if there is no data field.
     */
    public byte[] commandData() {
        byte[] body = getBody();
        if (body.length <= 5) {
            return new byte[0];
        }
        int lc = body[4] & 0xff;
        if (lc != 0) {
            int dataLen = Math.min(lc, body.length - 5);
            return Arrays.copyOfRange(body, 5, 5 + dataLen);
        }
        if (body.length < 7) {
            return new byte[0];
        }
        int extLen = ((body[5] & 0xff) << 8) | (body[6] & 0xff);
        int dataLen = Math.min(extLen, body.length - 7);
        return Arrays.copyOfRange(body, 7, 7 + dataLen);
    }

    /**
     * Identify the addressed slot of a SICCT command message (type {@code 6B}, CLA {@code 80}),
     * handling both direct coding (P1) and reference coding (ASN.1 FUI DO). Returns {@code null}
     * if this is not a SICCT terminal command.
     */
    public Byte getSicctTerminalCommandSlot() {
        if (raw == null || raw.length < 14 || raw[0] != (byte) 0x6b || raw[10] != (byte) 0x80) {
            log.warn("getSicctTerminalCommandSlot called with non-command / invalid SICCT message");
            return null;
        }
        byte p1 = raw[12];
        if (p1 != (byte) 0xFF || raw.length == 14) {
            return p1;
        }
        byte[] apduData = Arrays.copyOfRange(raw, 14, raw.length);
        try {
            Byte referenceCoded = tryFindSlotInCommandBody(apduData);
            return referenceCoded != null ? referenceCoded : (byte) 0xFF;
        } catch (Exception e) {
            log.warn("Could not extract reference-coded slot; assuming direct coding (0xFF)", e);
            return (byte) 0xFF;
        }
    }

    @Override
    public String toString() {
        return Hex.toHex(raw);
    }

    private Byte tryFindSlotInCommandBody(byte[] apduData) throws IOException {
        try (ASN1InputStream input = new ASN1InputStream(apduData)) {
            ASN1Primitive primitive;
            while ((primitive = input.readObject()) != null) {
                Byte b = iccSlotIfFuiDo(primitive);
                if (b != null) {
                    return b;
                }
                if (primitive instanceof ASN1TaggedObject fuConTagged
                        && fuConTagged.getTagNo() == 0x02
                        && fuConTagged.getTagClass() == 0x80
                        && fuConTagged.getBaseObject() instanceof ASN1Sequence fuConDo) {
                    for (ASN1Encodable fuDo : fuConDo) {
                        Byte fui = iccSlotIfFuiDo(fuDo);
                        if (fui != null) {
                            return fui;
                        }
                    }
                }
            }
        }
        return null;
    }

    private Byte iccSlotIfFuiDo(ASN1Encodable encodable) {
        if (encodable instanceof ASN1TaggedObject tagged
                && tagged.getTagNo() == 0x04
                && tagged.getTagClass() == 0x80
                && tagged.getBaseObject() instanceof ASN1OctetString octets
                && octets.getOctets().length == 2
                && octets.getOctets()[0] == 0x00) {
            return octets.getOctets()[1];
        }
        return null;
    }
}
