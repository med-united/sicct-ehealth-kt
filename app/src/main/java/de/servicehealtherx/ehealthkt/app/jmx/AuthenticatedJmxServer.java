package de.servicehealtherx.ehealthkt.app.jmx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.rmi.NoSuchObjectException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.Map;

/**
 * An authenticated RMI {@link JMXConnectorServer} for remote management. It requires
 * username/password authentication ({@link CtRoleAuthenticator}) and enforces {@link CtRole}-based
 * access ({@link CtRoleAccessForwarder}) on the eHealth-KT management MBean. RMI registry and the
 * RMI server object share one port so a single firewall rule suffices.
 */
public final class AuthenticatedJmxServer {

    private static final Logger log = LoggerFactory.getLogger(AuthenticatedJmxServer.class);

    private final int port;
    private final CtRoleAuthenticator authenticator;
    private final ObjectName managed;

    private Registry registry;
    private JMXConnectorServer connectorServer;

    public AuthenticatedJmxServer(int port, CtRoleAuthenticator authenticator) {
        this.port = port;
        this.authenticator = authenticator;
        try {
            this.managed = new ObjectName(EhealthKtManagementMBean.OBJECT_NAME);
        } catch (MalformedObjectNameException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Convenience factory: load accounts from a properties file. */
    public static AuthenticatedJmxServer fromUsersFile(int port, Path usersFile) {
        return new AuthenticatedJmxServer(port, CtRoleAuthenticator.fromUsersFile(usersFile));
    }

    public synchronized void start() throws IOException {
        registry = LocateRegistry.createRegistry(port);
        MBeanServer mbeanServer = ManagementFactory.getPlatformMBeanServer();

        Map<String, Object> env = new HashMap<>();
        env.put(JMXConnectorServer.AUTHENTICATOR, authenticator);

        JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://localhost:" + port
                + "/jndi/rmi://localhost:" + port + "/jmxrmi");
        connectorServer = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbeanServer);
        connectorServer.setMBeanServerForwarder(CtRoleAccessForwarder.create(managed));
        connectorServer.start();
        log.info("Authenticated JMX connector started at {}", connectorServer.getAddress());
    }

    /** The address clients connect to (available after {@link #start()}). */
    public synchronized JMXServiceURL address() {
        return connectorServer == null ? null : connectorServer.getAddress();
    }

    public synchronized void stop() {
        if (connectorServer != null) {
            try {
                connectorServer.stop();
            } catch (IOException e) {
                log.debug("Error stopping JMX connector server", e);
            }
            connectorServer = null;
        }
        if (registry != null) {
            try {
                UnicastRemoteObject.unexportObject(registry, true);
            } catch (NoSuchObjectException e) {
                log.debug("RMI registry already unexported", e);
            }
            registry = null;
        }
    }
}
