package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.IccStatus;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    void transmitNotifiesRemovalListenerWhenCardRemovedMidCommand() {
        AtomicInteger removedSlot = new AtomicInteger(-1);
        CardSlotManager mgr = new CardSlotManager(() -> List.of(new RemovedOnTransmitSlot(3)));
        mgr.setRemovalListener(removedSlot::set);

        assertThatThrownBy(() -> mgr.transmit(3, Hex.toBytes("00A4020C022F11")))
                .isInstanceOf(CardRemovedException.class);
        assertThat(removedSlot.get()).isEqualTo(3);
    }

    /** A slot that reports its card was pulled the moment a command is transmitted. */
    private static final class RemovedOnTransmitSlot implements CardSlot {
        private final int index;

        RemovedOnTransmitSlot(int index) {
            this.index = index;
        }

        @Override
        public int index() {
            return index;
        }

        @Override
        public IccStatus status() {
            return IccStatus.CC_ABSENT;
        }

        @Override
        public boolean isPresent() {
            return false;
        }

        @Override
        public byte[] atr() {
            return null;
        }

        @Override
        public IccStatus reset() {
            return IccStatus.CC_ABSENT;
        }

        @Override
        public void eject() {
        }

        @Override
        public byte[] transmit(byte[] commandApdu) {
            throw new CardRemovedException(index, new IllegalStateException("Card has been removed"));
        }

        @Override
        public boolean supportsSecurePinEntry() {
            return false;
        }

        @Override
        public byte[] verifyPinSecure(byte pinReference) {
            return null;
        }

        @Override
        public byte[] verifyPinPlain(byte pinReference, String pin) {
            return transmit(null);
        }
    }

    @Test
    void pinBlockFormat2Encoding() {
        // format-2: high nibble 0x2 + length, then digits, padded with 0xF
        assertThat(Hex.toHex(PinBlocks.encodeFormat2("123456"))).isEqualTo("26123456FFFFFFFF");
    }
}
