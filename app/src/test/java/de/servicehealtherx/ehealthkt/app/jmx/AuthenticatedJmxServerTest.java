package de.servicehealtherx.ehealthkt.app.jmx;

import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.terminal.SicctSessionRegistry;
import de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

class AuthenticatedJmxServerTest {

    private int port;
    private AuthenticatedJmxServer server;
    private ObjectName name;
    private final InMemoryPairingStore pairingStore = new InMemoryPairingStore();

    @BeforeEach
    void setUp() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        name = new ObjectName(EhealthKtManagementMBean.OBJECT_NAME);

        // Register the management bean on the platform server (the connector exposes it).
        MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
        if (mbs.isRegistered(name)) {
            mbs.unregisterMBean(name);
        }
        EhealthKtManagement mgmt = new EhealthKtManagement(4742, new SicctSessionRegistry(),
                pairingStore, new SoftwareTerminalIdentity(KeyType.EC),
                new JmxTerminalUi(new HeadlessUi(), 5_000), () -> { /* no-op restart */ });
        mbs.registerMBean(mgmt, name);

        CtRoleAuthenticator auth = new CtRoleAuthenticator(Map.of(
                "admin", new CtRoleAuthenticator.Account("s3cret", java.util.Set.of(CtRole.CT_ADMIN)),
                "operator", new CtRoleAuthenticator.Account("pin0000", java.util.Set.of(CtRole.CT_CONTROL))));
        server = new AuthenticatedJmxServer(port, auth);
        server.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (server != null) {
            server.stop();
        }
        MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
        if (mbs.isRegistered(name)) {
            mbs.unregisterMBean(name);
        }
    }

    private JMXConnector connect(String user, String password) throws Exception {
        JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://localhost:" + port
                + "/jndi/rmi://localhost:" + port + "/jmxrmi");
        return JMXConnectorFactory.connect(url, Map.of(
                JMXConnector.CREDENTIALS, new String[]{user, password}));
    }

    @Test
    void rejectsWrongPassword() {
        assertThatThrownBy(() -> connect("admin", "wrong")).isInstanceOf(SecurityException.class);
    }

    @Test
    void rejectsUnknownUser() {
        assertThatThrownBy(() -> connect("nobody", "x")).isInstanceOf(SecurityException.class);
    }

    @Test
    void adminMayReadAndAdminister() throws Exception {
        pairingStore.add(blockWith());
        try (JMXConnector c = connect("admin", "s3cret")) {
            var mbsc = c.getMBeanServerConnection();
            // read attribute
            assertThat(mbsc.getAttribute(name, "ActiveSessions")).isEqualTo(0);
            // admin-only operation succeeds
            assertThat(mbsc.invoke(name, "clearPairingBlocks", null, null)).isEqualTo(1);
        }
    }

    @Test
    void controlMayReadButNotAdminister() throws Exception {
        try (JMXConnector c = connect("operator", "pin0000")) {
            var mbsc = c.getMBeanServerConnection();

            // reads are allowed for CT_CONTROL
            assertThat(mbsc.getAttribute(name, "PairingBlocks")).isEqualTo(0);
            // operational op is allowed (passes the role gate; fails on no-pending business rule)
            Throwable confirm = catchThrowable(() ->
                    mbsc.invoke(name, "confirmPairing", null, null));
            assertThat(rootCauseTypes(confirm)).doesNotContain(SecurityException.class.getName());

            // admin-only op is denied for CT_CONTROL
            Throwable denied = catchThrowable(() ->
                    mbsc.invoke(name, "clearPairingBlocks", null, null));
            assertThat(rootCauseTypes(denied)).contains(SecurityException.class.getName());
        }
    }

    /** Collect the class names along the exception cause chain (JMX wraps server-side throwables). */
    private static java.util.List<String> rootCauseTypes(Throwable t) {
        java.util.List<String> types = new java.util.ArrayList<>();
        for (Throwable c = t; c != null; c = c.getCause()) {
            types.add(c.getClass().getName());
        }
        return types;
    }

    private static de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock blockWith() {
        var b = new de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock("aabb");
        b.addPublicKey("0401aa");
        return b;
    }
}
