package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.card.SimulatedCardSlotBackend;
import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.card.sim.VirtualCard;
import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.MessageType;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore;
import de.servicehealtherx.ehealthkt.ui.PinRequest;
import de.servicehealtherx.ehealthkt.ui.TerminalUi;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.AttributeKey;
import org.junit.jupiter.api.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** PERFORM VERIFICATION / MODIFY VERIFICATION DATA through the command interpreter. */
class PinVerificationTest {
    /** A Command-To-Perform DO (tag 52) around {@code control byte || insertion position(s) || APDU}. */
    private static String cmdDo(String valueHex) {
        return "52" + Hex.toHex((byte) (valueHex.length() / 2)) + valueHex;
    }


    private static final AttributeKey<SicctState> STATE = AttributeKey.valueOf("ehkt.state");

    /** Records every APDU it receives and answers with a fixed response. */
    private static final class RecordingCard implements VirtualCard {
        final List<String> received = new ArrayList<>();
        private final String responseHex;

        RecordingCard(String responseHex) {
            this.responseHex = responseHex;
        }

        @Override
        public byte[] atr() {
            return Hex.toBytes("3BD3960081B1FE451F07");
        }

        @Override
        public byte[] transmit(byte[] commandApdu) {
            received.add(Hex.toHex(commandApdu));
            return Hex.toBytes(responseHex);
        }
    }

    /** Answers PIN requests from a script and records what was requested and displayed. */
    private static final class ScriptedUi implements TerminalUi {
        final Deque<char[]> pins = new ArrayDeque<>();
        final List<PinRequest> requests = new ArrayList<>();
        final List<String> displayed = new ArrayList<>();
        boolean timeOut;

        ScriptedUi(String... pins) {
            for (String pin : pins) {
                this.pins.add(pin.toCharArray());
            }
        }

        @Override
        public void display(String line1, String line2) {
            displayed.add(line1);
        }

        @Override
        public char[] requestPin(PinRequest request) {
            requests.add(request);
            return timeOut ? null : pins.poll();
        }

        @Override
        public boolean confirm(String line1, String line2) {
            return true;
        }
    }

    private static EmbeddedChannel channel(SimulatedCardSlotBackend backend, TerminalUi ui) {
        InMemoryPairingStore pairing = new InMemoryPairingStore();
        EhealthTerminalAuthenticate auth =
                new EhealthTerminalAuthenticate(new SoftwareTerminalIdentity(KeyType.RSA), pairing, ui);
        EmbeddedChannel channel = new EmbeddedChannel(new SicctCommandInterpreter(new CardSlotManager(backend),
                ui, pairing, auth, KonnektorCertValidator.acceptAll(), new SicctSessionRegistry()));
        channel.attr(STATE).set(SicctState.CLIENT_WITH_PAIRING);
        return channel;
    }

    /** Send a terminal command {@code 80 INS P1(slot) 50 Lc data} and return the response body as hex. */
    private static String send(EmbeddedChannel channel, int ins, int slot, String dataHex) {
        byte[] data = Hex.toBytes(dataHex);
        byte[] apdu = Hex.concat(new byte[]{(byte) 0x80, (byte) ins, (byte) slot, 0x50, (byte) data.length}, data);
        channel.writeInbound(SicctMessage.of(MessageType.COMMAND, (short) 0, (short) 1, apdu));
        SicctMessage response = channel.readOutbound();
        assertThat(response).isNotNull();
        return Hex.toHex(response.getBody());
    }

    /**
     * Remote-PIN: the Konnektor addresses the gSMC-KT slot with a PSO ENCIPHER template; the terminal
     * inserts the PIN block and returns the card's cryptogram instead of a bare status word.
     */
    @Test
    void remotePinEnciphersThePinOnTheAddressedCardAndReturnsTheCryptogram() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        RecordingCard gsmcKt = new RecordingCard("01AABBCCDDEEFF00119000");
        backend.simulatedSlot(1).insert(gsmcKt);
        ScriptedUi ui = new ScriptedUi("123456");

        String message = Hex.toHex("PIN.CH Remote".getBytes());
        String response = send(channel(backend, ui), 0x18, 1,
                "500D" + message + "80013C" + cmdDo("0207" + "002A868009" + "01" + "20FFFFFFFFFFFFFF" + "00"));

        assertThat(response).isEqualTo("01AABBCCDDEEFF00119000");
        assertThat(gsmcKt.received).containsExactly("002A8680090126123456FFFFFFFF00");
        assertThat(ui.requests).singleElement().satisfies(request -> {
            assertThat(request.prompt()).isEqualTo("PIN.CH Remote");
            assertThat(request.slot()).isEqualTo(1);
            assertThat(request.timeoutSeconds()).isEqualTo(60);
        });
    }

    @Test
    void verifyReturnsTheCardStatusForAWrongPin() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        backend.simulatedSlot(2).insert(ScriptedVirtualCard.egk());
        String data = cmdDo("0206" + "0020008108" + "20FFFFFFFFFFFFFF");

        assertThat(send(channel(backend, new ScriptedUi("000000")), 0x18, 2, data)).isEqualTo("63C2");
        assertThat(send(channel(backend, new ScriptedUi("123456")), 0x18, 2, data)).isEqualTo("9000");
    }

    @Test
    void timeoutCancelAndInvalidEntryDoNotReachTheCard() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        RecordingCard card = new RecordingCard("9000");
        backend.simulatedSlot(2).insert(card);
        String data = cmdDo("0206" + "00200081");

        ScriptedUi timedOut = new ScriptedUi();
        timedOut.timeOut = true;
        assertThat(send(channel(backend, timedOut), 0x18, 2, data)).isEqualTo("6400");
        assertThat(send(channel(backend, new ScriptedUi("")), 0x18, 2, data)).isEqualTo("6401");
        assertThat(send(channel(backend, new ScriptedUi("12")), 0x18, 2, data)).isEqualTo("6400");
        assertThat(send(channel(backend, new ScriptedUi("12a4")), 0x18, 2, data)).isEqualTo("6400");
        assertThat(card.received).isEmpty();
    }

    @Test
    void emptyOrUnknownSlotAndBadCommandDataAreRejected() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        String data = cmdDo("0206" + "00200081");

        assertThat(send(channel(backend, new ScriptedUi("123456")), 0x18, 2, data)).isEqualTo("64A1");
        assertThat(send(channel(backend, new ScriptedUi("123456")), 0x18, 9, data)).isEqualTo("6A00");
        backend.simulatedSlot(2).insert(new RecordingCard("9000"));
        assertThat(send(channel(backend, new ScriptedUi("123456")), 0x18, 2, cmdDo("0206" + "00B00000")))
                .isEqualTo("6A80");
    }

    @Test
    void modifyAsksForOldNewAndRepeatedPin() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        RecordingCard card = new RecordingCard("9000");
        backend.simulatedSlot(2).insert(card);
        ScriptedUi ui = new ScriptedUi("123456", "654321", "654321");

        assertThat(send(channel(backend, ui), 0x1E, 2, cmdDo("02060E" + "00240081"))).isEqualTo("9000");
        assertThat(card.received).containsExactly("002400811026123456FFFFFFFF26654321FFFFFFFF");
        assertThat(ui.requests).extracting(PinRequest::prompt).containsExactly(
                "Bitte Geheimzahl eingeben", "Neue Geheimzahl eingeben", "Eingabe wiederholen");
    }

    @Test
    void modifyWithDifferingRepetitionIsAborted() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        RecordingCard card = new RecordingCard("9000");
        backend.simulatedSlot(2).insert(card);
        ScriptedUi ui = new ScriptedUi("123456", "654321", "654322");

        assertThat(send(channel(backend, ui), 0x1E, 2, cmdDo("02060E" + "00240081"))).isEqualTo("6402");
        assertThat(card.received).isEmpty();
        assertThat(ui.displayed).last().isEqualTo("Geheimzahl nicht gleich. Abbruch");
    }

    /** SICCT OUTPUT as sent by a Konnektor: APPL DO with soft breaks plus a waiting time DO. */
    @Test
    void outputShowsTheApplicationLabelText() {
        ScriptedUi ui = new ScriptedUi();
        String text = Hex.toHex("PIN ".getBytes()) + "0B" + Hex.toHex("erfolgreich ".getBytes()) + "0B"
                + Hex.toHex("verifiziert!".getBytes());

        String response = send(channel(new SimulatedCardSlotBackend(1), ui), 0x17, 0x40,
                "50" + Hex.toHex((byte) (text.length() / 2)) + text + "800100");

        assertThat(response).isEqualTo("9000");
        assertThat(ui.displayed).last().isEqualTo("PIN erfolgreich");
    }
}
