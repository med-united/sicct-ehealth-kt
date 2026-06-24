package de.servicehealtherx.ehealthkt.sicct.codec;

import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

/**
 * Netty encoder that writes a {@link SicctMessage}'s raw bytes onto the wire.
 */
public class SicctEncoder extends MessageToByteEncoder<SicctMessage> {

    @Override
    protected void encode(ChannelHandlerContext ctx, SicctMessage msg, ByteBuf out) {
        out.writeBytes(msg.getRaw());
    }
}
