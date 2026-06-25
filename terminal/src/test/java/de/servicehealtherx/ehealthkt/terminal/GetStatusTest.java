package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.card.SimulatedCardSlotBackend;
import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.MessageType;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AttributeKey;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GetStatusTest {

    private static final AttributeKey<SicctState> STATE = AttributeKey.valueOf("ehkt.state");

    private EmbeddedChannel channelWith(CardSlotManager cards) {
        HeadlessUi ui = HeadlessUi.withPin("123456");
        InMemoryPairingStore pairing = new InMemoryPairingStore();
        EhealthTerminalAuthenticate auth =
                new EhealthTerminalAuthenticate(new SoftwareTerminalIdentity(KeyType.RSA), pairing, ui);
        SicctCommandInterpreter interpreter = new SicctCommandInterpreter(
                cards, ui, pairing, auth, KonnektorCertValidator.acceptAll(), new SicctSessionRegistry());
        EmbeddedChannel channel = new EmbeddedChannel(interpreter);
        // GET STATUS is allowed for any valid client; skip the TLS handshake by setting the state.
        channel.attr(STATE).set(SicctState.CLIENT_WITHOUT_PAIRING);
        return channel;
    }

    /** GET STATUS, CT (FU 0), P2='80' -> ICC Status Data Object for all ICC interfaces. */
    private static SicctMessage getAllIccStatus() {
        byte[] apdu = {(byte) 0x80, 0x13, 0x00, (byte) 0x80, 0x00}; // CLA INS P1=CT P2=ICCS Le
        return SicctMessage.of(MessageType.COMMAND, (short) 0x0000, (short) 0x0001, apdu);
    }

    @Test
    void getAllIccStatusReturnsTlvWrappedStatusBytesPerSlot() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(3);
        backend.simulatedSlot(2).insert(ScriptedVirtualCard.egk()); // present, not powered -> 0x01
        EmbeddedChannel channel = channelWith(new CardSlotManager(backend));

        channel.writeInbound(getAllIccStatus());
        SicctMessage response = channel.readOutbound();

        assertThat(response).isNotNull();
        assertThat(response.type()).isEqualTo(MessageType.RESPONSE);
        // ICCS DO: tag 80, len 03, slot statuses (absent, present, absent), then SW 9000.
        assertThat(Hex.toHex(response.getBody())).isEqualTo("80030001009000");
    }

    @Test
    void getCardTerminalManufacturerReturnsCtmDoWithVersions() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(3);
        EmbeddedChannel channel = channelWith(new CardSlotManager(backend));

        // GET STATUS, CT (FU 0), P2='46' -> CardTerminal Manufacturer Data Object.
        byte[] apdu = {(byte) 0x80, 0x13, 0x00, (byte) 0x46, 0x00};
        channel.writeInbound(SicctMessage.of(MessageType.COMMAND, (short) 0x0000, (short) 0x0003, apdu));
        SicctMessage response = channel.readOutbound();

        assertThat(response).isNotNull();
        String body = Hex.toHex(response.getBody());
        // Outer CTM DO: tag 46, len 44 (=68 bytes), then ... then SW 9000.
        assertThat(body).startsWith("4644");
        assertThat(body).endsWith("9000");
        // CTM "DESRX" + CTT "0130 " + CTSV "0100 " (ASCII), then the DD DO (tag d7, len 33 = 51).
        assertThat(body).contains(Hex.toHex("DESRX0130 0100 ".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        assertThat(body).contains("D733");
        // VER = EHEALTH interface version 1.0.0 -> "  1  0  0" (each field space-left-padded to 3).
        assertThat(body).contains(Hex.toHex("  1  0  0".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        // PT = "KT".
        assertThat(body).contains(Hex.toHex("KT".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    }

    @Test
    void getStatusForSingleAddressedIccReturnsThatSlotOnly() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(3);
        backend.simulatedSlot(2).insert(ScriptedVirtualCard.egk());
        EmbeddedChannel channel = channelWith(new CardSlotManager(backend));

        byte[] apdu = {(byte) 0x80, 0x13, 0x02, (byte) 0x80, 0x00}; // P1 addresses ICC slot 2
        channel.writeInbound(SicctMessage.of(MessageType.COMMAND, (short) 0x0000, (short) 0x0002, apdu));
        SicctMessage response = channel.readOutbound();

        assertThat(response).isNotNull();
        // ICCS DO: tag 80, len 01, status of slot 2 (present), then SW 9000.
        assertThat(Hex.toHex(response.getBody())).isEqualTo("8001019000");
    }
}
