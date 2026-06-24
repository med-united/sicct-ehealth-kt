package de.servicehealtherx.ehealthkt.card.sim;

import de.servicehealtherx.ehealthkt.sicct.Hex;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A lightweight simulated card that answers a configured set of command APDUs and emulates a
 * single PIN. Sufficient to exercise SELECT / READ / VERIFY flows in tests without a full
 * JavaCard applet. For richer simulation, a jcardsim-backed {@link VirtualCard} can be supplied.
 */
public class ScriptedVirtualCard implements VirtualCard {

    private final byte[] atr;
    private final Map<String, byte[]> responses = new LinkedHashMap<>();
    private byte pinReference = (byte) 0x81;
    private String correctPin;
    private int pinTriesLeft = 3;

    public ScriptedVirtualCard(byte[] atr) {
        this.atr = atr.clone();
    }

    /** A default eGK-like simulated card (answers SELECT MF/AID and a READ BINARY). */
    public static ScriptedVirtualCard egk() {
        ScriptedVirtualCard c = new ScriptedVirtualCard(Hex.toBytes("3BD3960081B1FE451F07"));
        // SELECT by AID (eGK) -> OK
        c.on("00A4040007D2760001448000", "9000");
        // SELECT MF -> OK
        c.on("00A4000C023F00", "9000");
        // READ BINARY of a small EF -> sample data
        c.on("00B0000000", "0102030405069000");
        c.withPin((byte) 0x81, "123456");
        return c;
    }

    public ScriptedVirtualCard on(String commandHex, String responseHex) {
        responses.put(commandHex.toUpperCase(), Hex.toBytes(responseHex));
        return this;
    }

    public ScriptedVirtualCard withPin(byte pinReference, String correctPin) {
        this.pinReference = pinReference;
        this.correctPin = correctPin;
        return this;
    }

    @Override
    public byte[] atr() {
        return atr.clone();
    }

    @Override
    public byte[] transmit(byte[] commandApdu) {
        // VERIFY (INS 0x20) handling
        if (commandApdu.length >= 4 && commandApdu[1] == 0x20 && commandApdu[3] == pinReference) {
            return verify(commandApdu);
        }
        byte[] canned = responses.get(Hex.toHex(commandApdu));
        if (canned != null) {
            return canned;
        }
        return Hex.toBytes("6D00"); // instruction not supported
    }

    private byte[] verify(byte[] commandApdu) {
        if (correctPin == null) {
            return Hex.toBytes("9000");
        }
        if (commandApdu.length <= 5) {
            // no PIN block (e.g. status query); report remaining tries
            return new byte[]{0x63, (byte) (0xC0 | (pinTriesLeft & 0x0F))};
        }
        byte[] expected = de.servicehealtherx.ehealthkt.card.PinBlocks.encodeFormat2(correctPin);
        byte[] presented = new byte[commandApdu.length - 5];
        System.arraycopy(commandApdu, 5, presented, 0, presented.length);
        if (java.util.Arrays.equals(expected, presented)) {
            pinTriesLeft = 3;
            return Hex.toBytes("9000");
        }
        pinTriesLeft = Math.max(0, pinTriesLeft - 1);
        return new byte[]{0x63, (byte) (0xC0 | (pinTriesLeft & 0x0F))};
    }
}
