package de.servicehealtherx.ehealthkt.sicct;

import de.servicehealtherx.ehealthkt.sicct.codec.SicctEncoder;
import de.servicehealtherx.ehealthkt.sicct.codec.SicctFrameDecoder;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SicctMessageTest {

    @Test
    void buildsAndParsesEnvelope() {
        byte[] apdu = Hex.toBytes("80130063"); // GET STATUS, terminal status object
        SicctMessage msg = SicctMessage.of(MessageType.COMMAND, (short) 0x0000, (short) 0x0001, apdu);

        assertThat(msg.type()).isEqualTo(MessageType.COMMAND);
        assertThat(msg.getSlot()).isEqualTo((short) 0);
        assertThat(msg.getSeqShort()).isEqualTo((short) 1);
        assertThat(msg.getLength()).isEqualTo(4);
        assertThat(msg.getBody()).isEqualTo(apdu);
        assertThat(msg.getCla()).isEqualTo((byte) 0x80);
        assertThat(msg.getIns()).isEqualTo((byte) 0x13);
    }

    @Test
    void responseKeepsSlotAndSequence() {
        SicctMessage cmd = SicctMessage.of(MessageType.COMMAND, (short) 0x0005, (short) 0x0042,
                Hex.toBytes("80120000"));
        SicctMessage resp = cmd.toResponse(StatusWord.SUCCESS.toBytes());

        assertThat(resp.type()).isEqualTo(MessageType.RESPONSE);
        assertThat(resp.getSlot()).isEqualTo((short) 5);
        assertThat(resp.getSeqShort()).isEqualTo((short) 0x42);
        assertThat(resp.getBody()).isEqualTo(new byte[]{(byte) 0x90, 0x00});
    }

    @Test
    void frameDecoderHandlesSplitAndConcatenatedFrames() {
        SicctMessage a = SicctMessage.of(MessageType.COMMAND, (short) 0, (short) 1, Hex.toBytes("80130063"));
        SicctMessage b = SicctMessage.of(MessageType.COMMAND, (short) 2, (short) 2, Hex.toBytes("8011000101"));

        EmbeddedChannel ch = new EmbeddedChannel(new SicctFrameDecoder());
        // write encoded bytes, split arbitrarily across two reads
        byte[] all = Hex.concat(a.getRaw(), b.getRaw());
        ch.writeInbound(io.netty.buffer.Unpooled.wrappedBuffer(all, 0, 7));
        ch.writeInbound(io.netty.buffer.Unpooled.wrappedBuffer(all, 7, all.length - 7));

        SicctMessage d1 = ch.readInbound();
        SicctMessage d2 = ch.readInbound();
        assertThat(d1.getRaw()).isEqualTo(a.getRaw());
        assertThat(d2.getRaw()).isEqualTo(b.getRaw());
        assertThat((Object) ch.readInbound()).isNull();
    }

    @Test
    void encoderWritesRawBytes() {
        SicctMessage m = SicctMessage.of(MessageType.EVENT, (short) 0, (short) 0xFD00,
                new byte[]{(byte) 0x80});
        EmbeddedChannel ch = new EmbeddedChannel(new SicctEncoder());
        ch.writeOutbound(m);
        io.netty.buffer.ByteBuf out = ch.readOutbound();
        byte[] bytes = io.netty.buffer.ByteBufUtil.getBytes(out);
        assertThat(bytes).isEqualTo(m.getRaw());
    }

    @Test
    void tlvRoundTrip() {
        Tlv secret = new Tlv(0xD4, Hex.toBytes("00112233445566778899AABBCCDDEEFF"));
        Tlv label = new Tlv(0x50, "Konnektor".getBytes());
        byte[] encoded = Hex.concat(secret.toBytes(), label.toBytes());

        List<Tlv> parsed = Tlv.parseList(encoded);
        assertThat(parsed).hasSize(2);
        assertThat(Tlv.find(parsed, 0xD4).value()).isEqualTo(secret.value());
        assertThat(new String(Tlv.find(parsed, 0x50).value())).isEqualTo("Konnektor");
    }

    @Test
    void directCodingSlotIsReadFromP1() {
        // 6B envelope + SICCT command CLA=80 INS=12 P1=05 P2=F1
        SicctMessage m = SicctMessage.of(MessageType.COMMAND, (short) 0, (short) 1,
                Hex.toBytes("801205F1"));
        assertThat(m.getSicctTerminalCommandSlot()).isEqualTo((byte) 0x05);
    }
}
