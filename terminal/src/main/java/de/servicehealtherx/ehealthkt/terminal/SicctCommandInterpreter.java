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

    private static final Logger log = LoggerFactory.getLogger(SicctCommandInterpreter.class);

    private final CardSlotManager cards;
    private final TerminalUi ui;
    private final PairingStore pairingStore;
    private final EhealthTerminalAuthenticate authenticate;
    private final KonnektorCertValidator certValidator;

    public SicctCommandInterpreter(CardSlotManager cards, TerminalUi ui, PairingStore pairingStore,
                                   EhealthTerminalAuthenticate authenticate, KonnektorCertValidator certValidator) {
        this.cards = cards;
        this.ui = ui;
        this.pairingStore = pairingStore;
        this.authenticate = authenticate;
        this.certValidator = certValidator;
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
            case INS_RESET_CT -> reply(ctx, msg, StatusWord.SUCCESS.toBytes());
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
                // pairing may now exist; refresh state
                if (pairingStore.isPaired(clientKey)) {
                    ctx.attr(STATE).set(SicctState.CLIENT_WITH_PAIRING);
                }
            }
            case 0x02 -> { // VALIDATE
                payload = authenticate.validate(msg.commandData(), clientKey);
            }
            default -> {
                log.info("EHEALTH TERMINAL AUTHENTICATE P2={} not supported", Hex.toHex(p2));
                payload = StatusWord.INSTRUCTION_NOT_SUPPORTED.toBytes();
            }
        }
        reply(ctx, msg, payload);
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
        // ICC status object (P2=0x80): a status byte per slot
        if (p2 == (byte) 0x80) {
            byte[] statuses = new byte[cards.slots().size()];
            int i = 0;
            for (var slot : cards.slots()) {
                statuses[i++] = slot.status().value();
            }
            return Hex.concat(statuses, StatusWord.SUCCESS.toBytes());
        }
        // Other status objects: acknowledge with success (minimal functional response).
        return StatusWord.SUCCESS.toBytes();
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

    private static final class NotPairedException extends RuntimeException {
    }
}
