package de.servicehealtherx.ehealthkt.sicct.codec;

import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;

import java.util.List;

/**
 * Netty decoder that frames raw bytes into {@link SicctMessage}s using the 4-byte
 * length field of the SICCT envelope (offset 6). Waits until a full frame is available.
 */
public class SicctFrameDecoder extends ByteToMessageDecoder {

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (in.readableBytes() < SicctMessage.HEADER_LENGTH) {
            return;
        }
        in.markReaderIndex();
        int payloadLength = in.getInt(in.readerIndex() + 6);
        if (payloadLength < 0) {
            ctx.close();
            return;
        }
        int frameLength = SicctMessage.HEADER_LENGTH + payloadLength;
        if (in.readableBytes() < frameLength) {
            in.resetReaderIndex();
            return;
        }
        byte[] raw = ByteBufUtil.getBytes(in.readSlice(frameLength));
        out.add(new SicctMessage(raw));
    }
}
