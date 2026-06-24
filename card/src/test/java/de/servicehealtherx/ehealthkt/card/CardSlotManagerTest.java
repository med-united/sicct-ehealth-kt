package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.IccStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CardSlotManagerTest {

    @Test
    void requestEjectAndTransmitOnSimulatedEgk() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(2);
        backend.simulatedSlot(2).insert(ScriptedVirtualCard.egk());
        CardSlotManager mgr = new CardSlotManager(backend);

        assertThat(mgr.iccStatus(1)).isEqualTo(IccStatus.CC_ABSENT);
        assertThat(mgr.iccStatus(2)).isEqualTo(IccStatus.CC_PRESENT);

        assertThat(mgr.requestIcc(2)).isEqualTo(IccStatus.CC_SPECIFIC);
        assertThat(mgr.iccStatus(2)).isEqualTo(IccStatus.CC_SPECIFIC);
        assertThat(mgr.atr(2)).isNotNull();

        byte[] selectResp = mgr.transmit(2, Hex.toBytes("00A4040007D2760001448000"));
        assertThat(Hex.toHex(selectResp)).isEqualTo("9000");

        mgr.ejectIcc(2);
        assertThat(mgr.iccStatus(2)).isEqualTo(IccStatus.CC_PRESENT);
    }

    @Test
    void plainPinVerifySucceedsWithCorrectPin() {
        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(1);
        backend.simulatedSlot(1).insert(ScriptedVirtualCard.egk());
        CardSlotManager mgr = new CardSlotManager(backend);
        mgr.requestIcc(1);

        assertThat(mgr.supportsSecurePinEntry(1)).isFalse();
        byte[] ok = mgr.verifyPinPlain(1, (byte) 0x81, "123456");
        assertThat(Hex.toHex(ok)).isEqualTo("9000");

        byte[] wrong = mgr.verifyPinPlain(1, (byte) 0x81, "000000");
        assertThat(Hex.toHex(wrong)).startsWith("63C");
    }

    @Test
    void pinBlockFormat2Encoding() {
        // format-2: high nibble 0x2 + length, then digits, padded with 0xF
        assertThat(Hex.toHex(PinBlocks.encodeFormat2("123456"))).isEqualTo("26123456FFFFFFFF");
    }
}
