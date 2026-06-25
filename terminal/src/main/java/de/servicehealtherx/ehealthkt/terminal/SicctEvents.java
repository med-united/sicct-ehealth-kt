package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.sicct.EventTag;
import de.servicehealtherx.ehealthkt.sicct.MessageType;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import io.netty.channel.Channel;
import io.netty.util.AttributeKey;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Builds SICCT event messages (type {@code 0x50}) and assigns each connection a monotonic event
 * sequence number from the SICCT event range {@code FD00..FFFF}. The sequence is shared by every
 * event sent on a channel — keep-alive, sign-off and card insert/remove — so the Konnektor sees a
 * single ordered event stream.
 */
final class SicctEvents {

    /** Per-connection next event sequence number, lazily initialised to {@link #SEQ_START}. */
    private static final AttributeKey<AtomicInteger> EVENT_SEQ = AttributeKey.valueOf("ehkt.eventSeq");

    private static final int SEQ_START = 0xFD00;
    private static final int SEQ_END = 0xFFFF;

    private SicctEvents() {
    }

    /** An event whose payload is a single tag byte (keep-alive, sign-off). */
    static SicctMessage event(Channel channel, EventTag tag) {
        return SicctMessage.of(MessageType.EVENT, (short) 0x0000, nextSeq(channel),
                new byte[]{tag.value()});
    }

    /**
     * A card insert/remove event for an ICC slot. The payload is the BER-TLV
     * {@code <tag> 02 00 <slot>} carrying the 1-based slot index — the wire format the gematik
     * reference terminals use for {@link EventTag#CARD_INSERTED} / {@link EventTag#CARD_REMOVED}.
     */
    static SicctMessage cardEvent(Channel channel, EventTag tag, int slot) {
        byte[] payload = {tag.value(), 0x02, 0x00, (byte) slot};
        return SicctMessage.of(MessageType.EVENT, (short) 0x0000, nextSeq(channel), payload);
    }

    private static short nextSeq(Channel channel) {
        AtomicInteger seq = channel.attr(EVENT_SEQ).get();
        if (seq == null) {
            AtomicInteger created = new AtomicInteger(SEQ_START);
            AtomicInteger existing = channel.attr(EVENT_SEQ).setIfAbsent(created);
            seq = existing != null ? existing : created;
        }
        return (short) seq.getAndUpdate(v -> v >= SEQ_END ? SEQ_START : v + 1);
    }
}
