package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.card.CardSlotBackend;
import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.card.PcscCardSlotBackend;
import de.servicehealtherx.ehealthkt.card.SimulatedCardSlotBackend;
import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtCardIdentity;
import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.gsmckt.TerminalIdentity;
import de.servicehealtherx.ehealthkt.terminal.EhealthTerminalAuthenticate;
import de.servicehealtherx.ehealthkt.terminal.KonnektorCertValidator;
import de.servicehealtherx.ehealthkt.terminal.SicctCommandInterpreter;
import de.servicehealtherx.ehealthkt.terminal.SicctTlsServer;
import de.servicehealtherx.ehealthkt.terminal.pairing.FilePairingStore;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingStore;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import de.servicehealtherx.ehealthkt.ui.TerminalUi;
import io.netty.handler.ssl.SslContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Entry point for the standalone eHealth-KT. Wires the gSMC-KT identity, card slots, user interface
 * and pairing store and starts the SICCT TLS server (and service discovery).
 */
@Command(name = "ehealth-kt", mixinStandardHelpOptions = true, version = "eHealth-KT 1.0.0",
        description = "Standalone SICCT eHealth-Kartenterminal (gemSpec_KT).")
public class EhealthKtApplication implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(EhealthKtApplication.class);

    enum Mode {SIM, PCSC}

    enum UiKind {HEADLESS, JAVAFX}

    @Option(names = "--mode", description = "Card/identity backend: ${COMPLETION-CANDIDATES}. Default: SIM")
    Mode mode = Mode.SIM;

    @Option(names = "--port", description = "SICCT TLS port. Default: 4742")
    int port = SicctTlsServer.DEFAULT_PORT;

    @Option(names = "--key-type", description = "SIM identity key type: ${COMPLETION-CANDIDATES}. Default: RSA")
    KeyType keyType = KeyType.RSA;

    @Option(names = "--ui", description = "User interface: ${COMPLETION-CANDIDATES}. Default: HEADLESS")
    UiKind uiKind = UiKind.HEADLESS;

    @Option(names = "--pairing-file", description = "Pairing store file. Default: ./pairing.json")
    Path pairingFile = Path.of("pairing.json");

    @Option(names = "--egk-slot", description = "SIM mode: slot to insert a simulated eGK. Default: 2")
    int egkSlot = 2;

    @Option(names = "--sim-slots", description = "SIM mode: number of card slots. Default: 4")
    int simSlots = 4;

    @Option(names = "--pin", description = "HEADLESS UI: PIN to supply on PERFORM VERIFICATION. Default: 123456")
    String headlessPin = "123456";

    @Option(names = "--gsmckt-reader", description = "PCSC mode: PC/SC reader index of the gSMC-KT. Default: 0")
    int gsmcktReader = 0;

    @Option(names = "--terminal-name", description = "Terminal name announced via service discovery.")
    String terminalName = "eHealth-KT";

    @Option(names = "--no-discovery", description = "Disable UDP service discovery.")
    boolean noDiscovery;

    @Option(names = "--reader-idle", description = "Reader idle timeout (s). Default: 119")
    int readerIdle = 119;

    @Option(names = "--writer-idle", description = "Writer idle (keep-alive) timeout (s). Default: 30")
    int writerIdle = 30;

    @Override
    public Integer call() throws Exception {
        TerminalIdentity identity = buildIdentity();
        CardSlotBackend backend = buildCardBackend();
        CardSlotManager cards = new CardSlotManager(backend);
        TerminalUi ui = buildUi();
        PairingStore pairingStore = new FilePairingStore(pairingFile);
        EhealthTerminalAuthenticate authenticate = new EhealthTerminalAuthenticate(identity, pairingStore, ui);
        SslContext sslContext = buildSslContext(identity);

        SicctTlsServer server = new SicctTlsServer(port, sslContext,
                () -> new SicctCommandInterpreter(cards, ui, pairingStore, authenticate,
                        KonnektorCertValidator.acceptAll()),
                readerIdle, writerIdle);

        ServiceDiscoveryServer discovery = noDiscovery ? null : new ServiceDiscoveryServer(port, terminalName);
        FirmwareUpdateService firmware = FirmwareUpdateService.noop();
        ManagementInterface management = ManagementInterface.noop();

        int boundPort = server.start();
        if (discovery != null) {
            discovery.start();
        }
        management.start();
        firmware.checkForUpdate();
        ui.display(terminalName, "Ready :" + boundPort);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down eHealth-KT");
            if (discovery != null) {
                discovery.close();
            }
            management.stop();
            server.close();
            try {
                cards.close();
            } catch (Exception ignored) {
                // best effort
            }
        }));

        log.info("eHealth-KT '{}' running in {} mode on port {} ({} UI). Press Ctrl+C to stop.",
                terminalName, mode, boundPort, uiKind);
        Thread.currentThread().join();
        return 0;
    }

    private TerminalIdentity buildIdentity() {
        if (mode == Mode.SIM) {
            log.info("Using software gSMC-KT identity ({})", keyType);
            return new SoftwareTerminalIdentity(keyType);
        }
        CardTerminal terminal = pcscReader(gsmcktReader);
        try {
            return new GsmcKtCardIdentity(terminal.connect("*").getBasicChannel());
        } catch (Exception e) {
            throw new IllegalStateException("Could not open gSMC-KT in reader " + gsmcktReader, e);
        }
    }

    private CardSlotBackend buildCardBackend() {
        if (mode == Mode.SIM) {
            SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(simSlots);
            if (egkSlot >= 1 && egkSlot <= simSlots) {
                backend.simulatedSlot(egkSlot).insert(ScriptedVirtualCard.egk());
                log.info("Inserted simulated eGK into slot {}", egkSlot);
            }
            return backend;
        }
        return new PcscCardSlotBackend();
    }

    private TerminalUi buildUi() {
        if (uiKind == UiKind.JAVAFX) {
            try {
                return (TerminalUi) Class.forName("de.servicehealtherx.ehealthkt.ui.JavaFxTerminalUi")
                        .getDeclaredConstructor().newInstance();
            } catch (Throwable t) {
                log.warn("JavaFX UI not available ({}); falling back to headless. "
                        + "Build the ui module with -Pjavafx and add JavaFX to the runtime.", t.toString());
            }
        }
        return HeadlessUi.withPin(headlessPin);
    }

    private SslContext buildSslContext(TerminalIdentity identity) throws Exception {
        if (identity instanceof SoftwareTerminalIdentity sw) {
            return TlsContextFactory.forSoftwareIdentity(sw);
        }
        throw new IllegalStateException(
                "PCSC mode requires a gSMC-KT-backed TLS key manager, which is not yet wired. "
                        + "Run with --mode SIM, or supply a server keystore (see README).");
    }

    private static CardTerminal pcscReader(int index) {
        try {
            return TerminalFactory.getDefault().terminals().list().get(index);
        } catch (Exception e) {
            throw new IllegalStateException("No PC/SC reader at index " + index, e);
        }
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new EhealthKtApplication()).execute(args);
        System.exit(exitCode);
    }
}
