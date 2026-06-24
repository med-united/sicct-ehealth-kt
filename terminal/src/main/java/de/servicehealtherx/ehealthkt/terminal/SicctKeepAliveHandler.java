package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.sicct.EventTag;
import de.servicehealtherx.ehealthkt.sicct.MessageType;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Emits SICCT keep-alive events on writer idle and a terminal sign-off on reader idle (then closes),
 * per the SICCT event mechanism. Ported from the CardLink {@code SICCTKeepAliveHandler}.
 */
public class SicctKeepAliveHandler extends ChannelDuplexHandler {

    private static final Logger log = LoggerFactory.getLogger(SicctKeepAliveHandler.class);

    private short eventSeq = (short) 0xFD00; // SICCT event sequence range FD00..FFFF

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof IdleStateEvent idle) {
            if (idle.state() == IdleState.WRITER_IDLE) {
                ctx.writeAndFlush(event(EventTag.KEEP_ALIVE));
            } else if (idle.state() == IdleState.READER_IDLE) {
                log.info("Reader idle — sending sign-off and closing");
                ctx.writeAndFlush(event(EventTag.TERMINAL_SIGN_OFF));
                ctx.close();
            }
            return;
        }
        // Propagate all other user events (e.g. the TLS handshake completion) downstream.
        super.userEventTriggered(ctx, evt);
    }

    private SicctMessage event(EventTag tag) {
        if (eventSeq == (short) 0xFFFF) {
            eventSeq = (short) 0xFD00;
        }
        return SicctMessage.of(MessageType.EVENT, (short) 0x0000, eventSeq++, new byte[]{tag.value()});
    }
}
