package de.servicehealtherx.ehealthkt.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;

/**
 * A minimal SICCT service-discovery responder. Listens for UDP discovery requests on the SICCT port
 * and replies with the terminal name so a Konnektor can locate the eHealth-KT on the LAN
 * (distilled from the CardLink {@code ServiceDiscoveryUdpServer}).
 */
public class ServiceDiscoveryServer implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ServiceDiscoveryServer.class);

    private final int port;
    private final String terminalName;
    private volatile boolean running;
    private DatagramSocket socket;
    private Thread thread;

    public ServiceDiscoveryServer(int port, String terminalName) {
        this.port = port;
        this.terminalName = terminalName;
    }

    public void start() {
        try {
            socket = new DatagramSocket(port);
            socket.setBroadcast(true);
        } catch (Exception e) {
            log.warn("Service discovery disabled (could not bind UDP {}): {}", port, e.getMessage());
            return;
        }
        running = true;
        thread = new Thread(this::loop, "sicct-discovery");
        thread.setDaemon(true);
        thread.start();
        log.info("Service discovery listening on UDP {}", port);
    }

    private void loop() {
        byte[] buffer = new byte[512];
        while (running) {
            try {
                DatagramPacket request = new DatagramPacket(buffer, buffer.length);
                socket.receive(request);
                byte[] reply = ("SICCT:" + terminalName).getBytes(StandardCharsets.US_ASCII);
                socket.send(new DatagramPacket(reply, reply.length, request.getAddress(), request.getPort()));
                log.debug("Answered discovery from {}", request.getAddress());
            } catch (Exception e) {
                if (running) {
                    log.debug("Discovery loop error", e);
                }
            }
        }
    }

    @Override
    public void close() {
        running = false;
        if (socket != null) {
            socket.close();
        }
    }
}
