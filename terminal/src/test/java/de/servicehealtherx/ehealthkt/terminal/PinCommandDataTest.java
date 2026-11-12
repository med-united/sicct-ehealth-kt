package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.StatusWord;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PinCommandDataTest {
    /** A Command-To-Perform DO (tag 52) around {@code control byte || insertion position(s) || APDU}. */
    private static String cmdDo(String valueHex) {
        return "52" + Hex.toHex((byte) (valueHex.length() / 2)) + valueHex;
    }


    private static PinCommandData verify(String dataHex) {
        return PinCommandData.parse(Hex.toBytes(dataHex), false);
    }

    private static PinCommandData modify(String dataHex) {
        return PinCommandData.parse(Hex.toBytes(dataHex), true);
    }

    private static String apdu(PinCommandData command, String pin) {
        return Hex.toHex(command.buildApdu(pin.toCharArray()));
    }

    @Test
    void format2PinBlockOverwritesPreformattedDataField() {
        PinCommandData command = verify(cmdDo("0206" + "0020008108" + "20FFFFFFFFFFFFFF"));

        assertThat(command.format()).isEqualTo(PinCommandData.PinFormat.FORMAT_2);
        assertThat(command.minLength()).isEqualTo(4);
        assertThat(command.maxLength()).isEqualTo(12);
        assertThat(apdu(command, "123456")).isEqualTo("002000810826123456FFFFFFFF");
        assertThat(command.isPlainFormat2Verify()).isTrue();
    }

    @Test
    void format2PinBlockIsAppendedToHeaderOnlyTemplate() {
        PinCommandData command = verify(cmdDo("0206" + "00200081"));

        assertThat(apdu(command, "12345")).isEqualTo("00200081082512345FFFFFFFFF");
    }

    @Test
    void asciiAndBcdCodingAreSupported() {
        assertThat(apdu(verify(cmdDo("0106" + "00200001")), "1234")).isEqualTo("002000010431323334");
        assertThat(apdu(verify(cmdDo("0006" + "00200001")), "12345")).isEqualTo("002000010312345F");
        // BCD into a pre-padded field keeps the caller's padding nibbles.
        assertThat(apdu(verify(cmdDo("0006" + "0020000104" + "00000000")), "123"))
                .isEqualTo("002000010412300000");
    }

    @Test
    void controlByteCodesAFixedPinLength() {
        PinCommandData command = verify(cmdDo("6206" + "00200081"));

        assertThat(command.minLength()).isEqualTo(6);
        assertThat(command.maxLength()).isEqualTo(6);
    }

    /** Remote-PIN: the PIN block is inserted into a PSO ENCIPHER for the gSMC-KT; Le is preserved. */
    @Test
    void remotePinPsoEncipherKeepsPaddingIndicatorAndLe() {
        PinCommandData command = verify(cmdDo("0207" + "002A868009" + "01" + "20FFFFFFFFFFFFFF" + "00"));

        assertThat(apdu(command, "123456")).isEqualTo("002A8680090126123456FFFFFFFF00");
        assertThat(command.isPlainFormat2Verify()).isFalse();
    }

    @Test
    void insertionBeyondTheDataFieldGrowsItAndKeepsLe() {
        PinCommandData command = verify(cmdDo("0207" + "002A8680" + "01" + "01" + "00"));

        assertThat(apdu(command, "1234")).isEqualTo("002A868009" + "01" + "241234FFFFFFFFFF" + "00");
    }

    @Test
    void messagesWaitingTimeAndPinPromptAreDecoded() {
        // APPL DO "PIN{0B}eingeben{0F}PIN: " (ISO 646-DE), SMTBD DO with Latin-1 text, WT DO 60 s.
        String label = Hex.toHex("PIN".getBytes()) + "0B" + Hex.toHex(" f}r HBA".getBytes())
                + "0F" + Hex.toHex("PIN: ".getBytes());
        String smtbd = "A008" + "850101" + "0403" + "4FDC4B";
        PinCommandData command = verify("50" + Hex.toHex((byte) (label.length() / 2)) + label + smtbd
                + "80013C" + cmdDo("0206" + "00200081"));

        assertThat(command.message(0, "default").text()).isEqualTo("PIN für HBA");
        assertThat(command.message(0, "default").prompt()).isEqualTo("PIN: ");
        assertThat(command.message(1, "default").text()).isEqualTo("OÜK");
        assertThat(command.message(2, "default").text()).isEqualTo("default");
        assertThat(command.waitingTimeSeconds()).isEqualTo(60);
    }

    @Test
    void modifyInsertsOldAndNewPin() {
        PinCommandData command = modify(cmdDo("02060E" + "0024008110" + "20FFFFFFFFFFFFFF" + "20FFFFFFFFFFFFFF"));

        assertThat(Hex.toHex(command.buildApdu("123456".toCharArray(), "654321".toCharArray())))
                .isEqualTo("002400811026123456FFFFFFFF26654321FFFFFFFF");
        assertThat(command.skipsFirstPin()).isFalse();
    }

    @Test
    void modifyWithMinimumLengthForNewPinOnly() {
        PinCommandData command = modify(cmdDo("66060E" + "00240081"));

        assertThat(command.minLength()).isEqualTo(4);
        assertThat(command.maxLength()).isEqualTo(12);
        assertThat(command.newPinMinLength()).isEqualTo(6);
        assertThat(command.newPinMaxLength()).isEqualTo(12);
        assertThat(Hex.toHex(command.buildApdu("1234".toCharArray(), "654321".toCharArray())))
                .isEqualTo("0024008110241234FFFFFFFFFF26654321FFFFFFFF");
    }

    @Test
    void modifyNullPinSkipsTheFirstPin() {
        PinCommandData command = modify(cmdDo("020006" + "00240181"));

        assertThat(command.skipsFirstPin()).isTrue();
        assertThat(Hex.toHex(command.buildApdu(null, "123456".toCharArray())))
                .isEqualTo("002401810826123456FFFFFFFF");
    }

    @Test
    void invalidCommandDataIsRejected() {
        assertStatus("", StatusWord.WRONG_LENGTH);
        assertStatus("80011E", StatusWord.INCORRECT_DATA_FIELD);                       // no CMD DO
        assertStatus(cmdDo("0206" + "00B00000"), StatusWord.INCORRECT_DATA_FIELD);   // READ BINARY
        assertStatus(cmdDo("0206" + "002A9E9A"), StatusWord.INCORRECT_DATA_FIELD);   // PSO COMPUTE DS
        assertStatus(cmdDo("FF06" + "00200081"), StatusWord.INCORRECT_DATA_FIELD);   // biometric
        assertStatus(cmdDo("0206" + "00200081") + cmdDo("0206" + "00200081"), StatusWord.TOO_MANY_DATA_OBJECTS);
        assertStatus("52FF00", StatusWord.INCORRECT_DATA_FIELD);                       // truncated
    }

    @Test
    void insertionPositionInsideTheHeaderIsRejected() {
        PinCommandData command = verify(cmdDo("0203" + "00200081"));

        assertThatThrownBy(() -> command.buildApdu("1234".toCharArray()))
                .isInstanceOf(PinCommandData.InvalidPinCommandException.class);
    }

    private static void assertStatus(String dataHex, StatusWord expected) {
        assertThatThrownBy(() -> verify(dataHex))
                .isInstanceOfSatisfying(PinCommandData.InvalidPinCommandException.class,
                        e -> assertThat(e.statusWord()).isEqualTo(expected));
    }
}
