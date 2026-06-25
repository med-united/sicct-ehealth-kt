package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.IccStatus;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import de.servicehealtherx.ehealthkt.sicct.StatusWord;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingStore;
import de.servicehealtherx.ehealthkt.ui.PinRequest;
import de.servicehealtherx.ehealthkt.ui.TerminalUi;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.util.AttributeKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;

/**
 * The heart of the eHealth-KT: a Netty handler that interprets SICCT command messages, enforces
 * the connection state machine (gemSpec_KT) and dispatches to the card slots, the user interface
 * and the pairing logic. Refactored from the CardLink {@code SICCTCommandInterpreter} with all
 * cloud (JMS/SIEM/WebSocket) coupling removed.
 */
public class SicctCommandInterpreter extends SimpleChannelInboundHandler<SicctMessage> {

    // SICCT command instructions (CLA 0x80)
    private static final byte INS_RESET_CT = 0x11;
    private static final byte INS_REQUEST_ICC = 0x12;
    private static final byte INS_GET_STATUS = 0x13;
    private static final byte INS_EJECT_ICC = 0x15;
    private static final byte INS_OUTPUT = 0x17;
    private static final byte INS_PERFORM_VERIFICATION = 0x18;
    private static final byte INS_MODIFY_VERIFICATION = 0x1E;
    private static final byte INS_INIT_CT_SESSION = 0x28;
    private static final byte INS_CLOSE_CT_SESSION = 0x29;

    // eHealth terminal authenticate (CLA 0x81, INS 0xAA)
    private static final byte INS_EHEALTH_TERMINAL_AUTHENTICATE = (byte) 0xAA;

    private static final AttributeKey<String> CLIENT_KEY = AttributeKey.valueOf("ehkt.clientPublicKeyHex");
    private static final AttributeKey<SicctState> STATE = AttributeKey.valueOf("ehkt.state");
    /** The "EHEALTH EXPECT CHALLENGE RESPONSE" state: the ADD Phase 1 challenge awaiting Phase 2. */
    private static final AttributeKey<PendingChallenge> EXPECT_CHALLENGE =
            AttributeKey.valueOf("ehkt.expectChallengeResponse");

    /** EHEALTH EXPECT CHALLENGE RESPONSE timeout (gemSpec_KT TIP1-A_3115): max 30 seconds. */
    private static final long CHALLENGE_TTL_MILLIS = 30_000;

    private static final Logger log = LoggerFactory.getLogger(SicctCommandInterpreter.class);

    private final CardSlotManager cards;
    private final TerminalUi ui;
    private final PairingStore pairingStore;
    private final EhealthTerminalAuthenticate authenticate;
    private final KonnektorCertValidator certValidator;
    private final SicctSessionRegistry sessions;

    public SicctCommandInterpreter(CardSlotManager cards, TerminalUi ui, PairingStore pairingStore,
                                   EhealthTerminalAuthenticate authenticate, KonnektorCertValidator certValidator,
                                   SicctSessionRegistry sessions) {
        this.cards = cards;
        this.ui = ui;
        this.pairingStore = pairingStore;
        this.authenticate = authenticate;
        this.certValidator = certValidator;
        this.sessions = sessions;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if (evt instanceof SslHandshakeCompletionEvent handshake) {
            if (handshake.isSuccess()) {
                onHandshakeComplete(ctx);
            } else {
                log.warn("TLS handshake failed: {}", handshake.cause() == null ? "?" : handshake.cause().getMessage());
                ctx.attr(STATE).set(SicctState.INVALID_CLIENT);
            }
        }
        super.userEventTriggered(ctx, evt);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        sessions.unregister(ctx.channel());
        super.channelInactive(ctx);
    }

    private void onHandshakeComplete(ChannelHandlerContext ctx) {
        try {
            SslHandler ssl = ctx.pipeline().get(SslHandler.class);
            Certificate[] peer = ssl.engine().getSession().getPeerCertificates();
            if (peer == null || peer.length == 0 || !certValidator.isAcceptable(peer)) {
                ctx.attr(STATE).set(SicctState.INVALID_CLIENT);
                return;
            }
            String keyHex = Hex.toHex(peer[0].getPublicKey().getEncoded());
            ctx.attr(CLIENT_KEY).set(keyHex);
            ctx.attr(STATE).set(pairingStore.isPaired(keyHex)
                    ? SicctState.CLIENT_WITH_PAIRING : SicctState.CLIENT_WITHOUT_PAIRING);
            if (ctx.attr(STATE).get() == SicctState.CLIENT_WITH_PAIRING) {
                sessions.register(ctx.channel());
            }
            log.info("TLS client connected, state={}", ctx.attr(STATE).get());
        } catch (Exception e) {
            log.warn("Could not evaluate client certificate", e);
            ctx.attr(STATE).set(SicctState.INVALID_CLIENT);
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, SicctMessage msg) {
        SicctState state = stateOf(ctx);
        log.debug("RX {} (state={})", msg, state);
        if (state == SicctState.INVALID_CLIENT || state == SicctState.NO_SICCT_TLS) {
            reply(ctx, msg, StatusWord.COMMAND_NOT_ALLOWED_INVALID_CLIENT.toBytes());
            return;
        }
        try {
            dispatch(ctx, msg, state);
        } catch (NotPairedException e) {
            log.debug("Command rejected: not paired");
            reply(ctx, msg, StatusWord.COMMAND_NOT_ALLOWED_INVALID_CLIENT.toBytes());
        } catch (Exception e) {
            log.warn("Error processing {}", msg, e);
            reply(ctx, msg, StatusWord.NO_INFORMATION.toBytes());
        }
    }

    private void dispatch(ChannelHandlerContext ctx, SicctMessage msg, SicctState state) {
        // TIP1-A_3113: the EHEALTH EXPECT CHALLENGE RESPONSE state (and its challenge) is lost as
        // soon as any command other than EHEALTH TERMINAL AUTHENTICATE ADD Phase 2 (P2=04) runs.
        if (!isAddPhase2(msg)) {
            ctx.attr(EXPECT_CHALLENGE).set(null);
        }
        short slot = msg.getSlot();
        if (slot != 0) {
            // ISO-7816 APDU addressed to an ICC slot
            requirePairing(state);
            byte[] response = cards.transmit(slot, msg.getBody());
            reply(ctx, msg, response);
            return;
        }
        byte cla = msg.getCla();
        if (cla == (byte) 0x81 && msg.getIns() == INS_EHEALTH_TERMINAL_AUTHENTICATE) {
            handleEhealthAuthenticate(ctx, msg, state);
            return;
        }
        if (cla == (byte) 0x80) {
            handleSicctCommand(ctx, msg, state);
            return;
        }
        reply(ctx, msg, StatusWord.CLASS_NOT_SUPPORTED.toBytes());
    }

    private void handleSicctCommand(ChannelHandlerContext ctx, SicctMessage msg, SicctState state) {
        byte ins = msg.getIns();
        switch (ins) {
            case INS_INIT_CT_SESSION -> reply(ctx, msg, StatusWord.SUCCESS.toBytes());
            case INS_CLOSE_CT_SESSION -> reply(ctx, msg, StatusWord.SUCCESS.toBytes());
            case INS_GET_STATUS -> reply(ctx, msg, getStatus(msg));
            case INS_RESET_CT -> reply(ctx, msg, resetCtIcc(msg, state));
            case INS_REQUEST_ICC -> {
                requirePairing(state);
                reply(ctx, msg, requestIcc(msg));
            }
            case INS_EJECT_ICC -> {
                requirePairing(state);
                cards.ejectIcc(slotOf(msg));
                reply(ctx, msg, StatusWord.SUCCESS.toBytes());
            }
            case INS_OUTPUT -> {
                requirePairing(state);
                output(msg);
                reply(ctx, msg, StatusWord.SUCCESS.toBytes());
            }
            case INS_PERFORM_VERIFICATION -> {
                requirePairing(state);
                reply(ctx, msg, performVerification(msg));
            }
            case INS_MODIFY_VERIFICATION -> {
                requirePairing(state);
                reply(ctx, msg, modifyVerification(msg));
            }
            default -> reply(ctx, msg, StatusWord.INSTRUCTION_NOT_SUPPORTED.toBytes());
        }
    }

    private void handleEhealthAuthenticate(ChannelHandlerContext ctx, SicctMessage msg, SicctState state) {
        String clientKey = ctx.attr(CLIENT_KEY).get();
        byte p2 = msg.getP2();
        byte[] payload;
        switch (p2) {
            case 0x01 -> { // CREATE — allowed without pairing
                payload = authenticate.create(msg.commandData(), clientKey);
                // pairing may now exist; refresh state and start receiving card events
                if (pairingStore.isPaired(clientKey)) {
                    ctx.attr(STATE).set(SicctState.CLIENT_WITH_PAIRING);
                    sessions.register(ctx.channel());
                }
            }
            case 0x02 -> { // VALIDATE
                payload = authenticate.validate(msg.commandData(), clientKey);
            }
            case 0x03 -> { // ADD Phase 1 — generate challenge (allowed without pairing)
                byte[] challenge = authenticate.addPhase1(msg.getLe());
                if (challenge == null) {
                    payload = StatusWord.WRONG_LENGTH.toBytes();
                } else {
                    ctx.attr(EXPECT_CHALLENGE).set(
                            new PendingChallenge(challenge, System.currentTimeMillis() + CHALLENGE_TTL_MILLIS));
                    payload = challenge;
                }
            }
            case 0x04 -> { // ADD Phase 2 — verify shared-secret knowledge, bind this Konnektor key
                PendingChallenge pending = ctx.attr(EXPECT_CHALLENGE).get();
                ctx.attr(EXPECT_CHALLENGE).set(null); // leave EXPECT CHALLENGE RESPONSE regardless
                if (pending == null || pending.isExpired(System.currentTimeMillis())) {
                    log.info("ADD Phase 2 without a pending challenge (not in EXPECT CHALLENGE RESPONSE)");
                    payload = StatusWord.COMMAND_NOT_ALLOWED.toBytes();
                } else {
                    payload = authenticate.addPhase2(pending.challenge(), msg.commandData(), clientKey);
                    if (pairingStore.isPaired(clientKey)) {
                        ctx.attr(STATE).set(SicctState.CLIENT_WITH_PAIRING);
                        sessions.register(ctx.channel());
                    }
                }
            }
            default -> {
                log.info("EHEALTH TERMINAL AUTHENTICATE P2={} not supported", Hex.toHex(p2));
                payload = StatusWord.INSTRUCTION_NOT_SUPPORTED.toBytes();
            }
        }
        reply(ctx, msg, payload);
    }

    /**
     * SICCT RESET CT / ICC (INS 0x11). The addressed Functional Unit decides the success status
     * (SICCT 5.12.6): a RESET of the terminal (FU/slot 0) returns 9000, while a RESET of an ICC slot
     * returns SW2 = card type after reset — 01 for an asynchronous (processor) chipcard such as an
     * eGK/HBA/SMC-B, i.e. 9001. An empty slot yields 64A1 (no card present).
     */
    private byte[] resetCtIcc(SicctMessage msg, SicctState state) {
        int slot = slotOf(msg);
        if (slot == 0) {
            // RESET CT: reset the terminal and deactivate all slots; no chipcard type to qualify.
            return StatusWord.SUCCESS.toBytes();
        }
        // RESET ICC activates a chipcard (alternative to REQUEST ICC), so it requires a pairing.
        requirePairing(state);
        IccStatus status = cards.requestIcc(slot);
        if (status == null || status == IccStatus.CC_ABSENT) {
            return StatusWord.ICC_NOT_PRESENT.toBytes();
        }
        return StatusWord.RESET_ASYNC_SUCCESS.toBytes();
    }

    private byte[] requestIcc(SicctMessage msg) {
        int slot = slotOf(msg);
        IccStatus status = cards.requestIcc(slot);
        byte[] atr = cards.atr(slot);
        if (status == IccStatus.CC_SPECIFIC && atr != null) {
            return Hex.concat(atr, StatusWord.SUCCESS.toBytes());
        }
        return StatusWord.SICCT_CONTROL_RESPONSE.toBytes();
    }

    private void output(SicctMessage msg) {
        String text = new String(msg.commandData(), StandardCharsets.US_ASCII).trim();
        String line1 = text.length() > 16 ? text.substring(0, 16) : text;
        String line2 = text.length() > 16 ? text.substring(16, Math.min(32, text.length())) : "";
        ui.display(line1, line2);
    }

    private byte[] performVerification(SicctMessage msg) {
        int slot = slotOf(msg);
        byte pinReference = (byte) 0x81;
        if (cards.supportsSecurePinEntry(slot)) {
            ui.display("Enter PIN", "on reader");
            return cards.verifyPinSecure(slot, pinReference);
        }
        ui.display("Enter PIN", "for slot " + slot);
        char[] pin = ui.requestPin(PinRequest.forSlot(slot, pinReference));
        if (pin == null || pin.length == 0) {
            return StatusWord.COMMAND_TIMEOUT.toBytes();
        }
        try {
            return cards.verifyPinPlain(slot, pinReference, new String(pin));
        } finally {
            java.util.Arrays.fill(pin, '\0');
        }
    }

    private byte[] modifyVerification(SicctMessage msg) {
        // Functional stub: a full secure PIN change (old + new x2) would be orchestrated here.
        log.info("MODIFY VERIFICATION DATA requested for slot {} (not yet implemented)", slotOf(msg));
        return StatusWord.CONDITIONS_NOT_SATISFIED.toBytes();
    }

    private byte[] getStatus(SicctMessage msg) {
        byte p2 = msg.getP2();
        // ICC Status Data Object, P2='80' (SICCT 5.5.10.7 / 5.15.5): the response body is the
        // TLV  80 <len> <ICCSB...>  followed by SW 9000, one ICC status byte per slot. The CT
        // (FU/slot 0) is addressed for "all ICC interfaces"; a non-zero FU requests just that ICC.
        if (p2 == (byte) 0x80) {
            return iccStatusDataObject(slotOf(msg));
        }
        // Other status objects: acknowledge with success (minimal functional response).
        return StatusWord.SUCCESS.toBytes();
    }

    /** Build the ICC Status Data Object (ICCS DO) {@code 80 <len> <status bytes>} plus SW 9000. */
    private byte[] iccStatusDataObject(int addressedSlot) {
        byte[] statusBytes;
        if (addressedSlot == 0) {
            var slots = cards.slots();
            statusBytes = new byte[slots.size()];
            int i = 0;
            for (var slot : slots) {
                statusBytes[i++] = slot.status().value();
            }
        } else {
            statusBytes = new byte[]{cards.iccStatus(addressedSlot).value()};
        }
        // BER length is single-byte: SICCT addresses at most 14 ICC interfaces (len <= 127).
        byte[] iccsDo = new byte[2 + statusBytes.length];
        iccsDo[0] = (byte) 0x80;                // ICC Status Data Object tag
        iccsDo[1] = (byte) statusBytes.length;  // length = number of status bytes
        System.arraycopy(statusBytes, 0, iccsDo, 2, statusBytes.length);
        return Hex.concat(iccsDo, StatusWord.SUCCESS.toBytes());
    }

    private int slotOf(SicctMessage msg) {
        Byte slot = msg.getSicctTerminalCommandSlot();
        return slot == null ? 0 : (slot & 0xFF);
    }

    private SicctState stateOf(ChannelHandlerContext ctx) {
        SicctState state = ctx.attr(STATE).get();
        return state == null ? SicctState.NO_SICCT_TLS : state;
    }

    private void requirePairing(SicctState state) {
        if (state != SicctState.CLIENT_WITH_PAIRING) {
            throw new NotPairedException();
        }
    }

    private void reply(ChannelHandlerContext ctx, SicctMessage request, byte[] payload) {
        ctx.writeAndFlush(request.toResponse(payload));
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (cause instanceof NotPairedException) {
            log.debug("Command rejected: not paired");
            return;
        }
        log.warn("Channel exception", cause);
        ctx.close();
    }

    /** Whether {@code msg} is EHEALTH TERMINAL AUTHENTICATE ADD Phase 2 (CLA 81, INS AA, P2 04). */
    private boolean isAddPhase2(SicctMessage msg) {
        byte[] body = msg.getBody();
        return body.length >= 4
                && body[0] == (byte) 0x81
                && body[1] == INS_EHEALTH_TERMINAL_AUTHENTICATE
                && body[3] == 0x04;
    }

    private static final class NotPairedException extends RuntimeException {
    }

    /** A challenge generated by ADD Phase 1, awaiting the matching ADD Phase 2, with its deadline. */
    private record PendingChallenge(byte[] challenge, long expiresAtMillis) {
        boolean isExpired(long nowMillis) {
            return nowMillis > expiresAtMillis;
        }
    }
}
