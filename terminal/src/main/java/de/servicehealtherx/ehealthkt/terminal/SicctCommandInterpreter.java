package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardRemovedException;
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

    // SICCT standard display messages (5.19.2 / 5.20.2), used when the caller does not override them.
    private static final String MSG_ENTER_PIN = "Bitte Geheimzahl eingeben";
    private static final String MSG_SUCCESS = "Aktion erfolgreich";
    private static final String MSG_FAILED = "Geheimzahl falsch/gesperrt";
    private static final String MSG_ENTER_NEW_PIN = "Neue Geheimzahl eingeben";
    private static final String MSG_REPEAT_INPUT = "Eingabe wiederholen";
    private static final String MSG_NOT_IDENTICAL = "Geheimzahl nicht gleich. Abbruch";
    private static final String MSG_ABORT = "Abbruch";

    private static final Logger log = LoggerFactory.getLogger(SicctCommandInterpreter.class);

    private final CardSlotManager cards;
    private final TerminalUi ui;
    private final PairingStore pairingStore;
    private final EhealthTerminalAuthenticate authenticate;
    private final KonnektorCertValidator certValidator;
    private final SicctSessionRegistry sessions;
    private final boolean useReaderPinPad;

    public SicctCommandInterpreter(CardSlotManager cards, TerminalUi ui, PairingStore pairingStore,
                                   EhealthTerminalAuthenticate authenticate, KonnektorCertValidator certValidator,
                                   SicctSessionRegistry sessions) {
        this(cards, ui, pairingStore, authenticate, certValidator, sessions, true);
    }

    /**
     * @param useReaderPinPad whether a plain VERIFY may be delegated to the PIN pad of the PC/SC reader
     *                        holding the card; {@code false} forces every PIN through the {@link TerminalUi}
     */
    public SicctCommandInterpreter(CardSlotManager cards, TerminalUi ui, PairingStore pairingStore,
                                   EhealthTerminalAuthenticate authenticate, KonnektorCertValidator certValidator,
                                   SicctSessionRegistry sessions, boolean useReaderPinPad) {
        this.useReaderPinPad = useReaderPinPad;
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
        } catch (CardRemovedException e) {
            // The card was pulled mid-command: the CARD REMOVED event has already been raised and the
            // dead channel dropped (recreated on demand). Answer this command with "ICC not present".
            log.info("Card removed from slot {} during command; answered ICC not present", e.slot());
            reply(ctx, msg, StatusWord.ICC_NOT_PRESENT.toBytes());
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
            case INS_INIT_CT_SESSION -> reply(ctx, msg, initCtSession());
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
                    // Response APDU = <challenge> SW1 SW2, terminated by 9000.
                    payload = Hex.concat(challenge, StatusWord.SUCCESS.toBytes());
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

    /**
     * SICCT OUTPUT (INS 17, SICCT 5.18): show the message of the first Application Label / SICCT
     * Message-To-Be-Displayed DO on the two display lines, breaking at a word boundary.
     */
    private void output(SicctMessage msg) {
        String text = PinCommandData.firstDisplayText(msg.commandData());
        int split = text.length();
        if (text.length() > 24) {
            split = text.lastIndexOf(' ', 24);
            if (split <= 0) {
                split = 24;
            }
        }
        ui.display(text.substring(0, split).trim(), text.substring(split).trim());
    }

    /**
     * SICCT PERFORM VERIFICATION (INS 18, SICCT 5.19): ask the user for a PIN, insert it into the
     * chipcard command the caller supplied in the Command-To-Perform DO, send that command to the
     * addressed slot and return the card's response APDU unchanged.
     *
     * <p>The addressed slot may be the terminal's own gSMC-KT: that is the Remote-PIN procedure
     * (gemSpec_Kon TIP1-A_5012), where the command to perform is a PSO ENCIPHER and the response
     * carries the PIN cryptogram for a card in another terminal.
     */
    private byte[] performVerification(SicctMessage msg) {
        int slot = slotOf(msg);
        PinCommandData command;
        try {
            command = PinCommandData.parse(msg.commandData(), false);
        } catch (PinCommandData.InvalidPinCommandException e) {
            log.info("PERFORM VERIFICATION rejected: {}", e.getMessage());
            return e.statusWord().toBytes();
        }
        byte[] slotError = requireCardForPin(slot);
        if (slotError != null) {
            return slotError;
        }
        if (useReaderPinPad && command.isPlainFormat2Verify() && cards.supportsSecurePinEntry(slot)) {
            ui.display(command.message(0, MSG_ENTER_PIN).text(), "on reader");
            return showResult(command, cards.verifyPinSecure(slot, command.p2()));
        }
        char[] pin = null;
        byte[] apdu = null;
        try {
            pin = requestPin(command, 0, MSG_ENTER_PIN, slot, command.minLength(), command.maxLength());
            byte[] abort = abortStatus(command, 4, pin);
            if (abort != null) {
                return abort;
            }
            apdu = command.buildApdu(pin);
            return showResult(command, cards.transmit(slot, apdu));
        } catch (PinCommandData.InvalidPinCommandException e) {
            log.info("PERFORM VERIFICATION rejected: {}", e.getMessage());
            return e.statusWord().toBytes();
        } finally {
            wipe(pin);
            wipe(apdu);
        }
    }

    /**
     * SICCT MODIFY VERIFICATION DATA (INS 1E, SICCT 5.20): ask for the old PIN (unless the caller
     * requested the Null-PIN variant), the new PIN and its repetition, insert old and new PIN into
     * the supplied chipcard command and return the card's response APDU.
     */
    private byte[] modifyVerification(SicctMessage msg) {
        int slot = slotOf(msg);
        PinCommandData command;
        try {
            command = PinCommandData.parse(msg.commandData(), true);
        } catch (PinCommandData.InvalidPinCommandException e) {
            log.info("MODIFY VERIFICATION DATA rejected: {}", e.getMessage());
            return e.statusWord().toBytes();
        }
        byte[] slotError = requireCardForPin(slot);
        if (slotError != null) {
            return slotError;
        }
        char[] oldPin = null;
        char[] newPin = null;
        char[] repeated = null;
        byte[] apdu = null;
        try {
            if (!command.skipsFirstPin()) {
                oldPin = requestPin(command, 0, MSG_ENTER_PIN, slot, command.minLength(), command.maxLength());
                byte[] abort = abortStatus(command, 7, oldPin);
                if (abort != null) {
                    return abort;
                }
            }
            newPin = requestPin(command, 3, MSG_ENTER_NEW_PIN, slot,
                    command.newPinMinLength(), command.newPinMaxLength());
            byte[] abort = abortStatus(command, 7, newPin);
            if (abort != null) {
                return abort;
            }
            repeated = requestPin(command, 4, MSG_REPEAT_INPUT, slot,
                    command.newPinMinLength(), command.newPinMaxLength());
            abort = abortStatus(command, 7, repeated);
            if (abort != null) {
                return abort;
            }
            if (!java.util.Arrays.equals(newPin, repeated)) {
                ui.display(command.message(5, MSG_NOT_IDENTICAL).text(), "");
                return StatusWord.INPUT_NOT_IDENTICAL.toBytes();
            }
            apdu = command.buildApdu(oldPin, newPin);
            return showResult(command, cards.transmit(slot, apdu));
        } catch (PinCommandData.InvalidPinCommandException e) {
            log.info("MODIFY VERIFICATION DATA rejected: {}", e.getMessage());
            return e.statusWord().toBytes();
        } finally {
            wipe(oldPin);
            wipe(newPin);
            wipe(repeated);
            wipe(apdu);
        }
    }

    /** {@code null} if the addressed slot holds a card a PIN command can be sent to, else the error SW. */
    private byte[] requireCardForPin(int slot) {
        if (slot == 0 || cards.slot(slot).isEmpty()) {
            return StatusWord.WRONG_PARAMETERS_FUNCTIONAL_UNIT.toBytes();
        }
        if (cards.iccStatus(slot) == IccStatus.CC_ABSENT) {
            return StatusWord.ICC_NOT_PRESENT.toBytes();
        }
        return null;
    }

    private char[] requestPin(PinCommandData command, int messageIndex, String defaultText, int slot,
                              int minLength, int maxLength) {
        PinCommandData.DisplayMessage message = command.message(messageIndex, defaultText);
        ui.display(message.text(), message.prompt());
        return ui.requestPin(new PinRequest(message.text(), slot, command.p2(), minLength, maxLength,
                command.waitingTimeSeconds()));
    }

    /**
     * Evaluate a PIN entry: {@code null} if it is usable, otherwise the status word to return after
     * showing the abort message (timeout 6400, cancel 6401, wrong length/non-digit input 6400).
     */
    private byte[] abortStatus(PinCommandData command, int abortMessageIndex, char[] pin) {
        StatusWord status = null;
        if (pin == null) {
            status = StatusWord.INPUT_TIMEOUT;
        } else if (pin.length == 0) {
            status = StatusWord.INPUT_CANCELLED;
        } else if (!isAcceptablePin(pin)) {
            log.info("PIN entry rejected: {} characters, digits only, {}..{} allowed", pin.length,
                    PinCommandData.MIN_PIN_LENGTH, PinCommandData.MAX_PIN_LENGTH);
            status = StatusWord.INPUT_TIMEOUT;
        }
        if (status == null) {
            return null;
        }
        ui.display(command.message(abortMessageIndex, MSG_ABORT).text(), "");
        return status.toBytes();
    }

    private static boolean isAcceptablePin(char[] pin) {
        if (pin.length < PinCommandData.MIN_PIN_LENGTH || pin.length > PinCommandData.MAX_PIN_LENGTH) {
            return false;
        }
        for (char c : pin) {
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /** Postprocessing phase: show the success/failure message and hand the card's response back. */
    private byte[] showResult(PinCommandData command, byte[] response) {
        boolean success = response != null && response.length >= 2
                && response[response.length - 2] == (byte) 0x90 && response[response.length - 1] == 0x00;
        ui.display(success ? command.message(1, MSG_SUCCESS).text() : command.message(2, MSG_FAILED).text(), "");
        return response;
    }

    private static void wipe(char[] secret) {
        if (secret != null) {
            java.util.Arrays.fill(secret, '\0');
        }
    }

    private static void wipe(byte[] secret) {
        if (secret != null) {
            java.util.Arrays.fill(secret, (byte) 0);
        }
    }

    private byte[] getStatus(SicctMessage msg) {
        byte p2 = msg.getP2();
        // ICC Status Data Object, P2='80' (SICCT 5.5.10.7 / 5.15.5): the response body is the
        // TLV  80 <len> <ICCSB...>  followed by SW 9000, one ICC status byte per slot. The CT
        // (FU/slot 0) is addressed for "all ICC interfaces"; a non-zero FU requests just that ICC.
        if (p2 == (byte) 0x80) {
            return iccStatusDataObject(slotOf(msg));
        }
        // CardTerminal Manufacturer Data Object, P2='46' (SICCT 5.5.10.6): manufacturer, SICCT and
        // software versions plus the gemSpec_KT Discretionary Data DO (version fields), then SW 9000.
        if (p2 == CardTerminalManufacturerInfo.P2_CARD_TERMINAL_MANUFACTURER) {
            return Hex.concat(CardTerminalManufacturerInfo.dataObject(), StatusWord.SUCCESS.toBytes());
        }
        // CardTerminal Status Data Object, P2='63' (SICCT 5.5.10.5): functional units, ICC status and
        // the maximum APDU length. A Konnektor reads it right after INIT CT SESSION.
        if (p2 == (byte) 0x63) {
            byte[] value = Hex.concat(functionalUnitDataObject(), iccStatusTlv(0),
                    new byte[]{0x04, 0x02, (byte) 0x80, 0x0A}); // max. command/response APDU: 32778 bytes
            return Hex.concat(tlv(0x63, value), StatusWord.SUCCESS.toBytes());
        }
        // Functional Unit Data Object, P2='81' (SICCT 5.5.10.8).
        if (p2 == (byte) 0x81) {
            return Hex.concat(functionalUnitDataObject(), StatusWord.SUCCESS.toBytes());
        }
        // ICC Interface Capabilities Data Object, P2='66' (SICCT 5.5.10.16), per addressed slot.
        if (p2 == (byte) 0x66) {
            byte[] value = {
                    (byte) 0x80, 0x01, 0x01,               // card size: ID-1
                    (byte) 0x81, 0x01, 0x00,               // mechanical attributes: none
                    (byte) 0x82, 0x01, 0x57,               // card contacts
                    (byte) 0x83, 0x01, 0x03,               // card types
                    (byte) 0x84, 0x01, 0x43,               // asynchronous protocols (T=1)
                    (byte) 0x85, 0x01, 0x4F,               // synchronous protocols
                    (byte) 0x86, 0x01, 0x00,               // no contactless protocols
                    (byte) 0x87, 0x02, (byte) 0x80, 0x00}; // extended length: 32768 bytes
            return Hex.concat(tlv(0x66, value), StatusWord.SUCCESS.toBytes());
        }
        // Display Capabilities Data Object, P2='67' (SICCT 5.5.10.17).
        if (p2 == (byte) 0x67) {
            byte[] value = {
                    (byte) 0x80, 0x01, 0x30,   // 48 characters per line
                    (byte) 0x81, 0x01, 0x02,   // 2 visible lines
                    (byte) 0x82, 0x01, 0x00,   // no panning
                    (byte) 0x83, 0x01, 0x00,   // no scrolling
                    (byte) 0x84, 0x01, 0x00,   // no beeper / LED
                    (byte) 0x85, 0x01, 0x00,   // ISO 646
                    (byte) 0x85, 0x01, 0x01};  // ISO 8859-1
            return Hex.concat(tlv(0x67, value), StatusWord.SUCCESS.toBytes());
        }
        // Other status objects: acknowledge with success (minimal functional response).
        return StatusWord.SUCCESS.toBytes();
    }

    /**
     * SICCT INIT CT SESSION (INS 28, SICCT 5.10): answer with the CT Session Data Object
     * {@code 69 { 13 username, 13 password, 13 session id }}; user name and password are empty (the
     * Konnektor authenticates by TLS and pairing), the session id is assigned by the terminal.
     */
    private static byte[] initCtSession() {
        byte[] sessionId = "000000000001".getBytes(StandardCharsets.US_ASCII);
        byte[] value = Hex.concat(new byte[]{0x13, 0x00, 0x13, 0x00, 0x13, (byte) sessionId.length}, sessionId);
        return Hex.concat(tlv(0x69, value), StatusWord.SUCCESS.toBytes());
    }

    /**
     * Functional Unit Data Object {@code 81 <len> <FU type, FU index>...} (SICCT 5.5.10.8): one ICC
     * interface per card slot ({@code 00 nn}), the display ({@code 40 00}) and the keypad ({@code 50 00}).
     */
    private byte[] functionalUnitDataObject() {
        var slots = cards.slots();
        byte[] units = new byte[slots.size() * 2 + 4];
        int i = 0;
        for (var slot : slots) {
            units[i++] = 0x00;
            units[i++] = (byte) slot.index();
        }
        units[i++] = 0x40;
        units[i++] = 0x00;
        units[i++] = 0x50;
        units[i] = 0x00;
        return tlv(0x81, units);
    }

    private static byte[] tlv(int tag, byte[] value) {
        return new de.servicehealtherx.ehealthkt.sicct.Tlv(tag, value).toBytes();
    }

    /** Build the ICC Status Data Object (ICCS DO) {@code 80 <len> <status bytes>} plus SW 9000. */
    private byte[] iccStatusDataObject(int addressedSlot) {
        return Hex.concat(iccStatusTlv(addressedSlot), StatusWord.SUCCESS.toBytes());
    }

    /** The bare ICC Status Data Object {@code 80 <len> <status bytes>} without a status word. */
    private byte[] iccStatusTlv(int addressedSlot) {
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
        return iccsDo;
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
        SicctMessage response = request.toResponse(payload);
        log.debug("TX {}", response);
        ctx.writeAndFlush(response);
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
