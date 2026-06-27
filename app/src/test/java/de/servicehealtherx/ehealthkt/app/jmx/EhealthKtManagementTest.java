package de.servicehealtherx.ehealthkt.app.jmx;

import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import de.servicehealtherx.ehealthkt.ui.PinRequest;
import org.junit.jupiter.api.Test;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EhealthKtManagementTest {

    /** Spin until the condition holds or the deadline passes (avoids a test-only awaitility dep). */
    private static void awaitTrue(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not met within 2s");
            }
            Thread.sleep(10);
        }
    }

    /** A {@link LifecycleControl} that just records whether a restart was requested. */
    private static final class RecordingLifecycle implements LifecycleControl {
        volatile int restarts;

        @Override
        public void restart() {
            restarts++;
        }
    }

    private final RecordingLifecycle lifecycle = new RecordingLifecycle();
    private final de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore pairingStore =
            new de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore();

    private EhealthKtManagement newManagement(JmxTerminalUi ui) {
        return new EhealthKtManagement(4742,
                new de.servicehealtherx.ehealthkt.terminal.SicctSessionRegistry(),
                pairingStore, new SoftwareTerminalIdentity(KeyType.EC), ui, lifecycle);
    }

    private static de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock block(String secret,
                                                                                     String... keys) {
        var b = new de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock(secret);
        for (String k : keys) {
            b.addPublicKey(k);
        }
        return b;
    }

    @Test
    void confirmPairingReleasesParkedConfirm() throws Exception {
        JmxTerminalUi ui = new JmxTerminalUi(new HeadlessUi(), 5_000);
        EhealthKtManagement mgmt = newManagement(ui);

        CompletableFuture<Boolean> result =
                CompletableFuture.supplyAsync(() -> ui.confirm("Pair with", "Konnektor-1"));

        awaitTrue(mgmt::isPairingPending);
        assertThat(mgmt.getPairingPrompt()).contains("Konnektor-1");

        mgmt.confirmPairing();
        assertThat(result.get(2, TimeUnit.SECONDS)).isTrue();
        assertThat(mgmt.isPairingPending()).isFalse();
    }

    @Test
    void rejectPairingDeniesConfirm() throws Exception {
        JmxTerminalUi ui = new JmxTerminalUi(new HeadlessUi(), 5_000);
        EhealthKtManagement mgmt = newManagement(ui);

        CompletableFuture<Boolean> result =
                CompletableFuture.supplyAsync(() -> ui.confirm("Pair with", "Konnektor-2"));
        awaitTrue(mgmt::isPairingPending);

        mgmt.rejectPairing();
        assertThat(result.get(2, TimeUnit.SECONDS)).isFalse();
    }

    @Test
    void enterPinReleasesParkedPin() throws Exception {
        JmxTerminalUi ui = new JmxTerminalUi(new HeadlessUi(), 5_000);
        EhealthKtManagement mgmt = newManagement(ui);

        CompletableFuture<char[]> result =
                CompletableFuture.supplyAsync(() -> ui.requestPin(PinRequest.forSlot(1, (byte) 0x81)));
        awaitTrue(mgmt::isPinPending);

        mgmt.enterPin("123456");
        assertThat(result.get(2, TimeUnit.SECONDS)).containsExactly("123456".toCharArray());
        assertThat(mgmt.isPinPending()).isFalse();
    }

    @Test
    void operationsWithoutPendingRequestThrow() {
        JmxTerminalUi ui = new JmxTerminalUi(new HeadlessUi(), 5_000);
        EhealthKtManagement mgmt = newManagement(ui);

        assertThatThrownBy(mgmt::confirmPairing).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> mgmt.enterPin("123456")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> mgmt.enterPin("")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void exposesGsmcKtCertificateAsPem() {
        JmxTerminalUi ui = new JmxTerminalUi(new HeadlessUi(), 5_000);
        EhealthKtManagement mgmt = newManagement(ui);

        assertThat(mgmt.getGsmcKtKeyType()).isEqualTo("EC");
        assertThat(mgmt.getGsmcKtSubject()).isNotBlank();
        assertThat(mgmt.getGsmcKtCertificatePem())
                .startsWith("-----BEGIN CERTIFICATE-----")
                .contains("-----END CERTIFICATE-----");
    }

    @Test
    void listsAndRemovesPairingBlocks() {
        EhealthKtManagement mgmt = newManagement(new JmxTerminalUi(new HeadlessUi(), 5_000));
        pairingStore.add(block("aabb", "0401aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        pairingStore.add(block("ccdd", "0402bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "0403cccc"));

        assertThat(mgmt.getPairingBlocks()).isEqualTo(2);
        assertThat(mgmt.getBoundKonnektorKeys()).isEqualTo(3);
        assertThat(mgmt.listPairingBlocks()).contains("[0]", "[1]", "konnektorKeys=1", "konnektorKeys=2");
        // secrets are not leaked
        assertThat(mgmt.listPairingBlocks()).doesNotContain("aabb").contains("set (2 bytes)");

        assertThat(mgmt.removePairingBlock(0)).contains("Removed pairing block 0");
        assertThat(mgmt.getPairingBlocks()).isEqualTo(1);
        assertThatThrownBy(() -> mgmt.removePairingBlock(5)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void removesPairingBlockByKey() {
        EhealthKtManagement mgmt = newManagement(new JmxTerminalUi(new HeadlessUi(), 5_000));
        pairingStore.add(block("aabb", "0401aaaaaaaaaaaa"));

        assertThat(mgmt.removePairingBlockByKey("0401aaaaaaaaaaaa")).contains("Removed");
        assertThat(mgmt.getPairingBlocks()).isZero();
        assertThatThrownBy(() -> mgmt.removePairingBlockByKey("deadbeef"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void clearPairingBlocksEmptiesStore() {
        EhealthKtManagement mgmt = newManagement(new JmxTerminalUi(new HeadlessUi(), 5_000));
        pairingStore.add(block("aabb", "0401aa"));
        pairingStore.add(block("ccdd", "0402bb"));

        assertThat(mgmt.clearPairingBlocks()).isEqualTo(2);
        assertThat(mgmt.getPairingBlocks()).isZero();
        assertThat(mgmt.listPairingBlocks()).isEqualTo("No pairing blocks stored.");
    }

    @Test
    void restartDelegatesToLifecycle() {
        EhealthKtManagement mgmt = newManagement(new JmxTerminalUi(new HeadlessUi(), 5_000));
        assertThat(mgmt.restart()).contains("Restart");
        assertThat(lifecycle.restarts).isEqualTo(1);
    }

    @Test
    void factoryResetWipesPairingBlocksThenRestarts() {
        EhealthKtManagement mgmt = newManagement(new JmxTerminalUi(new HeadlessUi(), 5_000));
        pairingStore.add(block("aabb", "0401aa"));
        pairingStore.add(block("ccdd", "0402bb"));

        String result = mgmt.restartWithFactoryDefaults();
        assertThat(result).contains("wiped 2");
        assertThat(mgmt.getPairingBlocks()).isZero();
        assertThat(lifecycle.restarts).isEqualTo(1);
    }

    @Test
    void registersAndUnregistersMBean() throws Exception {
        JmxTerminalUi ui = new JmxTerminalUi(new HeadlessUi(), 5_000);
        EhealthKtManagement mgmt = newManagement(ui);
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        ObjectName name = new ObjectName(EhealthKtManagementMBean.OBJECT_NAME);

        mgmt.start();
        try {
            assertThat(server.isRegistered(name)).isTrue();
            assertThat(server.getAttribute(name, "ActiveSessions")).isEqualTo(0);
            assertThat((String) server.getAttribute(name, "ConnectionState")).contains("port 4742");
        } finally {
            mgmt.stop();
        }
        assertThat(server.isRegistered(name)).isFalse();
    }
}
