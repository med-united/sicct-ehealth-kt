package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.sicct.EventTag;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks the active, paired SICCT/TLS sessions so terminal-initiated events (card insert/remove)
 * can be pushed to every connected Konnektor. A channel registers once its pairing is established
 * and unregisters when the connection closes. Thread-safe: the {@link CardPresenceMonitor} broadcasts
 * from its own thread while channels register/unregister on Netty event-loop threads.
 */
public class SicctSessionRegistry {

    private static final Logger log = LoggerFactory.getLogger(SicctSessionRegistry.class);

    private final Set<Channel> sessions = ConcurrentHashMap.newKeySet();

    /** Register a paired session; idempotent. The session is removed automatically when it closes. */
    public void register(Channel channel) {
        if (sessions.add(channel)) {
            log.debug("Registered SICCT session {} ({} active)", channel.remoteAddress(), sessions.size());
            channel.closeFuture().addListener(f -> unregister(channel));
        }
    }

    public void unregister(Channel channel) {
        if (sessions.remove(channel)) {
            log.debug("Unregistered SICCT session {} ({} active)", channel.remoteAddress(), sessions.size());
        }
    }

    /** Number of active sessions. */
    public int size() {
        return sessions.size();
    }

    /** Push a card insert/remove event for the given 1-based slot to every active session. */
    public void broadcastCardEvent(EventTag tag, int slot) {
        for (Channel channel : sessions) {
            if (channel.isActive()) {
                channel.writeAndFlush(SicctEvents.cardEvent(channel, tag, slot));
            }
        }
    }
}
