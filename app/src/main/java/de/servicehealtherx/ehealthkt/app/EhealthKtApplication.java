package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.card.PcscCardSlotBackend;
import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtCardIdentity;
import de.servicehealtherx.ehealthkt.terminal.CardPresenceMonitor;
import de.servicehealtherx.ehealthkt.terminal.EhealthTerminalAuthenticate;
import de.servicehealtherx.ehealthkt.terminal.KonnektorCertValidator;
import de.servicehealtherx.ehealthkt.terminal.SicctCommandInterpreter;
import de.servicehealtherx.ehealthkt.terminal.SicctSessionRegistry;
import de.servicehealtherx.ehealthkt.terminal.SicctTlsServer;
import de.servicehealtherx.ehealthkt.terminal.pairing.FilePairingStore;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingStore;
import de.servicehealtherx.ehealthkt.app.pki.GematikKonnektorTrust;
import de.servicehealtherx.ehealthkt.app.pki.TslDownloader;
import de.servicehealtherx.ehealthkt.app.jmx.AuthenticatedJmxServer;
import de.servicehealtherx.ehealthkt.app.jmx.EhealthKtManagement;
import de.servicehealtherx.ehealthkt.app.jmx.JmxTerminalUi;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import de.servicehealtherx.ehealthkt.ui.TerminalUi;
import io.netty.handler.ssl.SslContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.net.ssl.TrustManager;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Entry point for the standalone eHealth-KT. The terminal runs against physical PC/SC readers: it
 * scans every connected reader for a gSMC-KT to use as its TLS server identity, binds the remaining
 * readers as card slots (re-scanning for newly connected readers while it runs), wires the user
 * interface and pairing store and starts the SICCT TLS server (and service discovery).
 */
@Command(name = "ehealth-kt", mixinStandardHelpOptions = true, version = "eHealth-KT 1.0.0",
        description = "Standalone SICCT eHealth-Kartenterminal (gemSpec_KT).")
public class EhealthKtApplication implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(EhealthKtApplication.class);

    enum UiKind {HEADLESS, JAVAFX}

    @Option(names = "--port", description = "SICCT TLS port. Default: 4742")
    int port = SicctTlsServer.DEFAULT_PORT;

    @Option(names = "--ui", description = "User interface: ${COMPLETION-CANDIDATES}. Default: HEADLESS")
    UiKind uiKind = UiKind.HEADLESS;

    @Option(names = "--pairing-file", description = "Pairing store file. Default: ./pairing.json")
    Path pairingFile = Path.of("pairing.json");

    @Option(names = "--pin", description = "HEADLESS UI: PIN to supply on PERFORM VERIFICATION. Default: 123456")
    String headlessPin = "123456";

    @Option(names = "--tsl-production", description = "Use the production (PU) gematik TSL instead of "
            + "the reference/test (RU) TSL. Default: false (use RU for TEST-ONLY cards).")
    boolean tslProduction;

    @Option(names = "--tsl-cache-dir", description = "Directory for the cached gematik TSL. "
            + "Default: ./tsl-cache")
    Path tslCacheDir = Path.of("tsl-cache");

    @Option(names = "--no-konnektor-trust", description = "Skip gematik TUC_PKI_018 validation of the "
            + "Konnektor client certificate (accept any chain). For local testing only.")
    boolean noKonnektorTrust;

    @Option(names = "--terminal-name", description = "Terminal name announced via service discovery.")
    String terminalName = "eHealth-KT";

    @Option(names = "--no-discovery", description = "Disable UDP service discovery.")
    boolean noDiscovery;

    @Option(names = "--jmx", description = "Enable the JMX management interface (confirm pairing, "
            + "enter PIN, connection state, gSMC-KT certificate). When enabled, pairing confirmations "
            + "and host PIN entry are answered over JMX instead of by the local UI. Default: false.")
    boolean jmx;

    @Option(names = "--jmx-timeout", description = "Seconds to wait for a JMX confirmation/PIN before "
            + "failing safe (deny/cancel). Default: 120")
    int jmxTimeout = 120;

    @Option(names = "--jmx-remote-port", description = "Enable an authenticated remote JMX connector "
            + "(RMI) on this port with CT_ADMIN/CT_CONTROL role-based access. Requires --jmx and "
            + "--jmx-users-file. Default: 0 (disabled; local JMX only).")
    int jmxRemotePort;

    @Option(names = "--jmx-users-file", description = "Properties file of JMX accounts for remote "
            + "access: 'user = password, ROLE[, ROLE]' (roles: CT_ADMIN, CT_CONTROL).")
    Path jmxUsersFile;

    @Option(names = "--reader-idle", description = "Reader idle timeout (s). Default: 119")
    int readerIdle = 119;

    @Option(names = "--writer-idle", description = "Writer idle (keep-alive) timeout (s). Default: 30")
    int writerIdle = 30;

    @Override
    public Integer call() throws Exception {
        GsmcKtCardIdentity identity = discoverGsmcKt();
        CardSlotManager cards = new CardSlotManager(new PcscCardSlotBackend());
        // When JMX management is enabled, route pairing confirmations and host PIN entry through the
        // JMX bridge UI; otherwise keep the local UI (headless auto-confirm / JavaFX).
        JmxTerminalUi jmxUi = jmx ? new JmxTerminalUi(buildUi(), jmxTimeout * 1000L) : null;
        TerminalUi ui = jmxUi != null ? jmxUi : buildUi();
        PairingStore pairingStore = new FilePairingStore(pairingFile);
        EhealthTerminalAuthenticate authenticate = new EhealthTerminalAuthenticate(identity, pairingStore, ui);
        SslContext sslContext = buildSslContext(identity);

        SicctSessionRegistry sessions = new SicctSessionRegistry();
        CardPresenceMonitor cardMonitor = new CardPresenceMonitor(cards, sessions);
        // Raise a CARD REMOVED event the instant a command detects the card was pulled, rather than
        // waiting for the next presence poll.
        cards.setRemovalListener(cardMonitor::cardRemoved);

        SicctTlsServer server = new SicctTlsServer(port, sslContext,
                () -> new SicctCommandInterpreter(cards, ui, pairingStore, authenticate,
                        KonnektorCertValidator.acceptAll(), sessions),
                readerIdle, writerIdle);

        ServiceDiscoveryServer discovery = noDiscovery ? null : new ServiceDiscoveryServer(port, terminalName);
        FirmwareUpdateService firmware = FirmwareUpdateService.noop();

        int boundPort = server.start();
        if (discovery != null) {
            discovery.start();
        }

        AuthenticatedJmxServer jmxServer = buildAuthenticatedJmx();

        // Tear down everything that holds the SICCT port, the JMX port or a PC/SC reader. Shared by
        // the JVM shutdown hook and the JMX restart (which releases these before relaunching).
        AtomicBoolean tornDown = new AtomicBoolean();
        Runnable teardown = () -> {
            if (!tornDown.compareAndSet(false, true)) {
                return;
            }
            log.info("Shutting down eHealth-KT");
            if (jmxServer != null) {
                jmxServer.stop();
            }
            if (discovery != null) {
                discovery.close();
            }
            server.close();
            cardMonitor.close();
            try {
                cards.close();
            } catch (Exception ignored) {
                // best effort
            }
        };

        ManagementInterface management = jmxUi != null
                ? new EhealthKtManagement(boundPort, sessions, pairingStore, identity, jmxUi,
                        new ProcessRestarter(teardown))
                : ManagementInterface.noop();
        management.start();
        if (jmxServer != null) {
            jmxServer.start();
            log.info("Authenticated remote JMX (CT_ADMIN/CT_CONTROL) enabled on port {}", jmxRemotePort);
        }
        firmware.checkForUpdate();
        ui.display(terminalName, "Ready :" + boundPort);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            teardown.run();
            management.stop();
        }));

        log.info("eHealth-KT '{}' running on port {} ({} UI). Press Ctrl+C to stop.",
                terminalName, boundPort, uiKind);
        Thread.currentThread().join();
        return 0;
    }

    /**
     * Scan every connected PC/SC reader for a gSMC-KT and return the first usable one. Empty readers,
     * and readers holding a card that is not a gSMC-KT, are skipped — an empty reader is normal.
     */
    private GsmcKtCardIdentity discoverGsmcKt() {
        List<CardTerminal> readers;
        try {
            readers = TerminalFactory.getDefault().terminals().list();
        } catch (Exception e) {
            throw new IllegalStateException("Could not enumerate PC/SC readers", e);
        }
        if (readers.isEmpty()) {
            throw new IllegalStateException("No PC/SC readers connected; cannot find a gSMC-KT");
        }
        for (CardTerminal reader : readers) {
            try {
                if (!reader.isCardPresent()) {
                    log.debug("Reader '{}' is empty, skipping gSMC-KT probe", reader.getName());
                    continue;
                }
                GsmcKtCardIdentity identity =
                        new GsmcKtCardIdentity(reader.connect("*").getBasicChannel());
                log.info("Using gSMC-KT in PC/SC reader '{}'", reader.getName());
                return identity;
            } catch (Exception e) {
                log.debug("Reader '{}' does not hold a usable gSMC-KT: {}", reader.getName(), e.toString());
            }
        }
        throw new IllegalStateException("No gSMC-KT found in any of the " + readers.size()
                + " connected PC/SC reader(s)");
    }

    /**
     * Build the authenticated remote JMX connector when {@code --jmx-remote-port} is set, or return
     * {@code null} to keep JMX local-only. Requires {@code --jmx} (so the management bean exists) and
     * a {@code --jmx-users-file}.
     */
    private AuthenticatedJmxServer buildAuthenticatedJmx() {
        if (jmxRemotePort <= 0) {
            return null;
        }
        if (!jmx) {
            throw new IllegalArgumentException("--jmx-remote-port requires --jmx");
        }
        if (jmxUsersFile == null) {
            throw new IllegalArgumentException("--jmx-remote-port requires --jmx-users-file");
        }
        return AuthenticatedJmxServer.fromUsersFile(jmxRemotePort, jmxUsersFile);
    }

    private TerminalUi buildUi() {
        if (uiKind == UiKind.JAVAFX) {
            try {
                return (TerminalUi) Class.forName("de.servicehealtherx.ehealthkt.ui.JavaFxTerminalUi")
                        .getDeclaredConstructor().newInstance();
            } catch (Throwable t) {
                Throwable cause = t instanceof java.lang.reflect.InvocationTargetException && t.getCause() != null
                        ? t.getCause() : t;
                log.warn("JavaFX UI not available; falling back to headless. "
                        + "Build the ui module with -Pjavafx and add JavaFX to the runtime.", cause);
            }
        }
        return HeadlessUi.withPin(headlessPin);
    }

    private SslContext buildSslContext(GsmcKtCardIdentity card) throws Exception {
        TrustManager konnektorTrust = null;
        if (!noKonnektorTrust) {
            log.info("Loading gematik {} TSL for Konnektor TUC_PKI_018 validation",
                    tslProduction ? "production (PU)" : "reference/test (RU)");
            TslDownloader tsl = new TslDownloader(tslProduction, tslCacheDir);
            tsl.refresh();
            konnektorTrust = GematikKonnektorTrust.clientTrustManager(tsl);
        } else {
            log.warn("Konnektor TUC_PKI_018 validation disabled (--no-konnektor-trust); accepting any client cert");
        }
        return TlsContextFactory.forCardIdentity(card, konnektorTrust);
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new EhealthKtApplication()).execute(args);
        System.exit(exitCode);
    }
}
