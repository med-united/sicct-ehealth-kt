package de.servicehealtherx.ehealthkt.app.jmx;

import de.servicehealtherx.ehealthkt.app.ManagementInterface;
import de.servicehealtherx.ehealthkt.gsmckt.TerminalIdentity;
import de.servicehealtherx.ehealthkt.terminal.SicctSessionRegistry;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import java.lang.management.ManagementFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Standard-MBean implementation of {@link EhealthKtManagementMBean}, backed by the live terminal
 * components. Registers itself with the platform MBean server on {@link #start()} and unregisters
 * on {@link #stop()}.
 *
 * <p>Pairing confirmation and PIN entry are delegated to the {@link JmxTerminalUi} the application
 * installed as the active terminal UI; connection state is read from the {@link SicctSessionRegistry}
 * and {@link PairingStore}; the certificate is read from the {@link TerminalIdentity} (gSMC-KT).
 */
public class EhealthKtManagement implements EhealthKtManagementMBean, ManagementInterface {

    private static final Logger log = LoggerFactory.getLogger(EhealthKtManagement.class);

    private final int port;
    private final SicctSessionRegistry sessions;
    private final PairingStore pairingStore;
    private final TerminalIdentity identity;
    private final JmxTerminalUi ui;
    private final LifecycleControl lifecycle;

    private volatile ObjectName objectName;

    public EhealthKtManagement(int port, SicctSessionRegistry sessions, PairingStore pairingStore,
                               TerminalIdentity identity, JmxTerminalUi ui, LifecycleControl lifecycle) {
        this.port = port;
        this.sessions = sessions;
        this.pairingStore = pairingStore;
        this.identity = identity;
        this.ui = ui;
        this.lifecycle = lifecycle;
    }

    @Override
    public void start() {
        try {
            MBeanServer server = ManagementFactory.getPlatformMBeanServer();
            objectName = new ObjectName(OBJECT_NAME);
            if (server.isRegistered(objectName)) {
                server.unregisterMBean(objectName);
            }
            server.registerMBean(this, objectName);
            log.info("Management interface: JMX MBean registered as {}", OBJECT_NAME);
        } catch (Exception e) {
            throw new IllegalStateException("Could not register JMX management MBean", e);
        }
    }

    @Override
    public void stop() {
        ObjectName name = objectName;
        if (name == null) {
            return;
        }
        try {
            ManagementFactory.getPlatformMBeanServer().unregisterMBean(name);
            log.info("Management interface: JMX MBean unregistered");
        } catch (Exception e) {
            log.debug("Failed to unregister JMX management MBean", e);
        } finally {
            objectName = null;
        }
    }

    // --- Connection state ---

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public int getActiveSessions() {
        return sessions.size();
    }

    @Override
    public int getPairingBlocks() {
        return pairingStore.all().size();
    }

    @Override
    public int getBoundKonnektorKeys() {
        return pairingStore.all().stream()
                .mapToInt(b -> b.getPublicKeysHex().size())
                .sum();
    }

    @Override
    public String getConnectionState() {
        return String.format(
                "SICCT TLS on port %d | active sessions: %d | pairing blocks: %d (%d Konnektor keys)%s%s",
                port, getActiveSessions(), getPairingBlocks(), getBoundKonnektorKeys(),
                ui.isConfirmPending() ? " | PAIRING PENDING: " + ui.confirmPrompt() : "",
                ui.isPinPending() ? " | PIN PENDING: " + ui.pinPrompt() : "");
    }

    // --- Pairing block management ---

    @Override
    public String listPairingBlocks() {
        List<PairingBlock> blocks = pairingStore.all();
        if (blocks.isEmpty()) {
            return "No pairing blocks stored.";
        }
        StringBuilder sb = new StringBuilder(blocks.size() + " pairing block(s):\n");
        for (int i = 0; i < blocks.size(); i++) {
            PairingBlock block = blocks.get(i);
            sb.append('[').append(i).append("] secret=").append(mask(block.getSharedSecretHex()))
                    .append(", konnektorKeys=").append(block.getPublicKeysHex().size());
            for (String key : block.getPublicKeysHex()) {
                sb.append("\n      - ").append(shorten(key));
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    @Override
    public String removePairingBlock(int index) {
        List<PairingBlock> blocks = pairingStore.all();
        if (index < 0 || index >= blocks.size()) {
            throw new IllegalArgumentException("No pairing block at index " + index
                    + " (have " + blocks.size() + ")");
        }
        PairingBlock block = blocks.get(index);
        pairingStore.remove(block);
        log.info("Removed pairing block {} via JMX ({} Konnektor key(s))", index,
                block.getPublicKeysHex().size());
        return "Removed pairing block " + index;
    }

    @Override
    public String removePairingBlockByKey(String publicKeyHex) {
        if (publicKeyHex == null || publicKeyHex.isBlank()) {
            throw new IllegalArgumentException("Public key must not be empty");
        }
        PairingBlock block = pairingStore.findByPublicKey(publicKeyHex.trim())
                .orElseThrow(() -> new IllegalArgumentException(
                        "No pairing block is bound to public key " + shorten(publicKeyHex)));
        pairingStore.remove(block);
        log.info("Removed pairing block bound to {} via JMX", shorten(publicKeyHex));
        return "Removed pairing block bound to " + shorten(publicKeyHex);
    }

    @Override
    public int clearPairingBlocks() {
        int removed = pairingStore.all().size();
        pairingStore.clear();
        log.warn("Cleared all {} pairing block(s) via JMX", removed);
        return removed;
    }

    private static String mask(String secretHex) {
        if (secretHex == null || secretHex.isEmpty()) {
            return "(none)";
        }
        return "set (" + (secretHex.length() / 2) + " bytes)";
    }

    private static String shorten(String hex) {
        if (hex == null) {
            return "(null)";
        }
        return hex.length() <= 24 ? hex : hex.substring(0, 24) + "…";
    }

    // --- Confirm pairing ---

    @Override
    public boolean isPairingPending() {
        return ui.isConfirmPending();
    }

    @Override
    public String getPairingPrompt() {
        return ui.confirmPrompt();
    }

    @Override
    public void confirmPairing() {
        if (!ui.resolveConfirm(true)) {
            throw new IllegalStateException("No pairing confirmation is pending");
        }
        log.info("Pairing confirmed via JMX");
    }

    @Override
    public void rejectPairing() {
        if (!ui.resolveConfirm(false)) {
            throw new IllegalStateException("No pairing confirmation is pending");
        }
        log.info("Pairing rejected via JMX");
    }

    // --- Enter a PIN ---

    @Override
    public boolean isPinPending() {
        return ui.isPinPending();
    }

    @Override
    public String getPinPrompt() {
        return ui.pinPrompt();
    }

    @Override
    public void enterPin(String pin) {
        if (pin == null || pin.isEmpty()) {
            throw new IllegalArgumentException("PIN must not be empty");
        }
        if (!ui.resolvePin(pin.toCharArray())) {
            throw new IllegalStateException("No PIN entry is pending");
        }
        log.info("PIN supplied via JMX ({} digits)", pin.length());
    }

    @Override
    public void cancelPin() {
        if (!ui.resolvePin(null)) {
            throw new IllegalStateException("No PIN entry is pending");
        }
        log.info("PIN entry cancelled via JMX");
    }

    // --- gSMC-KT certificate ---

    @Override
    public String getGsmcKtSubject() {
        return identity.getCertificate().getSubjectX500Principal().getName();
    }

    @Override
    public String getGsmcKtIssuer() {
        return identity.getCertificate().getIssuerX500Principal().getName();
    }

    @Override
    public String getGsmcKtSerial() {
        return identity.getCertificate().getSerialNumber().toString(16);
    }

    @Override
    public String getGsmcKtKeyType() {
        return identity.getKeyType().name();
    }

    @Override
    public String getGsmcKtValidFrom() {
        return identity.getCertificate().getNotBefore().toInstant()
                .toString();
    }

    @Override
    public String getGsmcKtValidUntil() {
        return identity.getCertificate().getNotAfter().toInstant()
                .toString();
    }

    @Override
    public String getGsmcKtCertificatePem() {
        X509Certificate cert = identity.getCertificate();
        try {
            String body = Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(cert.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Could not encode gSMC-KT certificate", e);
        }
    }

    // --- Lifecycle ---

    @Override
    public String restart() {
        log.warn("Restart requested via JMX");
        lifecycle.restart();
        return "Restart scheduled";
    }

    @Override
    public String restartWithFactoryDefaults() {
        log.warn("Factory-reset restart requested via JMX");
        int removed = clearPairingBlocks();
        lifecycle.restart();
        return "Factory reset: wiped " + removed + " pairing block(s); restart scheduled";
    }
}
