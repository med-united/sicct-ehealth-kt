package de.servicehealtherx.ehealthkt.ui;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HeadlessUiTest {

    @Test
    void displayLinesAreStored() {
        HeadlessUi ui = new HeadlessUi();
        ui.display("eHealth-KT", "Ready");
        assertThat(ui.line1()).isEqualTo("eHealth-KT");
        assertThat(ui.line2()).isEqualTo("Ready");
    }

    @Test
    void returnsScriptedPinAndConfirmation() {
        HeadlessUi ui = HeadlessUi.withPin("123456");
        char[] pin = ui.requestPin(PinRequest.forSlot(2, (byte) 0x81));
        assertThat(pin).containsExactly('1', '2', '3', '4', '5', '6');
        assertThat(ui.confirm("Pair with", "Konnektor?")).isTrue();
    }

    @Test
    void noPinConfiguredReturnsNull() {
        HeadlessUi ui = new HeadlessUi();
        assertThat(ui.requestPin(PinRequest.forSlot(1, (byte) 0x81))).isNull();
    }
}
