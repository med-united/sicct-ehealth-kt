package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.sicct.Tlv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * SICCT service-discovery responder (SICCT v1.2.3 §6.2.3). A Konnektor broadcasts a discovery
 * request on the SICCT UDP port; the terminal answers, unicast, with a description of itself so the
 * Konnektor can locate the eHealth-KT on the LAN.
 *
 * <p>Both request and response are BER-TLV:
 * <pre>
 *   request  A0 { 80 protocol-version, 81 konnektor-ip, 82 reply-port }
 *   response A1 { 80 protocol-version, 81 own-ip, 83 own-mac, 84 host, 82 sicct-port, A3 security }
 * </pre>
 * The response is sent to the IP / port the Konnektor named in the request (default UDP 4742).
 * Ported from the CardLink {@code ServiceDiscoveryRequestHandler}/{@code ServiceDiscoveryUdpClient}.
 */
public class ServiceDiscoveryServer implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ServiceDiscoveryServer.class);

    // SICCT v1.2.3 service-discovery BER-TLV tags (§6.2.3).
    private static final int TAG_REQUEST = 0xA0;
    private static final int TAG_RESPONSE = 0xA1;
    private static final int TAG_PROTOCOL_VERSION = 0x80;
    private static final int TAG_IP_ADDRESS = 0x81;
    private static final int TAG_PORT = 0x82;
    private static final int TAG_MAC_ADDRESS = 0x83;
    private static final int TAG_HOST = 0x84;
    private static final int TAG_SECURITY_PROTOCOL = 0xA3;
    private static final byte TAG_TLS = (byte) 0x8A;
    private static final byte SECURITY_TLS_1_2 = 0x30;
    /** Protocol version 1.20 (matches the reference Konnektor handshake). */
    private static final byte[] PROTOCOL_VERSION = {0x01, 0x14};

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
                handle(request);
            } catch (Exception e) {
                if (running) {
                    log.debug("Discovery loop error", e);
                }
            }
        }
    }

    private void handle(DatagramPacket request) throws Exception {
        byte[] data = Arrays.copyOf(request.getData(), request.getLength());
        Tlv envelope = Tlv.find(Tlv.parseList(data), TAG_REQUEST);
        if (envelope == null) {
            log.debug("Ignoring non-discovery UDP packet from {}", request.getAddress());
            return;
        }
        List<Tlv> req = Tlv.parseList(envelope.value());
        Tlv ipTlv = Tlv.find(req, TAG_IP_ADDRESS);
        Tlv portTlv = Tlv.find(req, TAG_PORT);

        // Where the Konnektor expects the reply (SICCT v1.2.3 §6.2.3.1: default UDP 4742).
        InetAddress konnektorIp = ipTlv != null && ipTlv.value().length == 4
                ? InetAddress.getByAddress(ipTlv.value())
                : request.getAddress();
        int replyPort = portTlv != null ? toUnsignedInt(portTlv.value()) : request.getPort();

        // Advertise our own address on the interface facing the Konnektor, plus that NIC's MAC.
        NetworkInterface nic = interfaceTowards(konnektorIp);
        Inet4Address localIp = ipv4Of(nic);
        if (localIp == null) {
            log.warn("Service discovery: no local IPv4 address to advertise; dropping request from {}", konnektorIp);
            return;
        }
        byte[] mac = nic.getHardwareAddress() != null ? nic.getHardwareAddress() : new byte[6];

        byte[] reply = buildResponse(localIp, mac, terminalName, port);
        socket.send(new DatagramPacket(reply, reply.length, konnektorIp, replyPort));
        log.info("Answered service discovery from {} -> advertised {}:{} (reply to {}:{}, {} bytes)",
                request.getAddress().getHostAddress(), localIp.getHostAddress(), port,
                konnektorIp.getHostAddress(), replyPort, reply.length);
    }

    /** Build the A1 discovery-response describing this terminal (pure; package-private for testing). */
    static byte[] buildResponse(Inet4Address localIp, byte[] mac, String terminalName, int port) {
        ByteArrayOutputStream inner = new ByteArrayOutputStream();
        inner.writeBytes(new Tlv(TAG_PROTOCOL_VERSION, PROTOCOL_VERSION).toBytes());
        inner.writeBytes(new Tlv(TAG_IP_ADDRESS, localIp.getAddress()).toBytes());
        inner.writeBytes(new Tlv(TAG_MAC_ADDRESS, mac).toBytes());
        inner.writeBytes(new Tlv(TAG_HOST, hostBytes(terminalName)).toBytes());
        inner.writeBytes(new Tlv(TAG_PORT, new byte[] {(byte) (port >> 8), (byte) port}).toBytes());
        inner.writeBytes(new Tlv(TAG_SECURITY_PROTOCOL,
                new byte[] {TAG_TLS, 0x01, SECURITY_TLS_1_2}).toBytes());
        return new Tlv(TAG_RESPONSE, inner.toByteArray()).toBytes();
    }

    /** Terminal name as ASCII, dots replaced by hyphens, capped at the SICCT 31-char limit. */
    private static byte[] hostBytes(String terminalName) {
        String name = terminalName.replace('.', '-');
        if (name.length() > 31) {
            name = name.substring(0, 31);
        }
        return name.getBytes(StandardCharsets.US_ASCII);
    }

    /** The up, non-loopback interface whose IPv4 subnet contains {@code peer}, else the first such interface. */
    private static NetworkInterface interfaceTowards(InetAddress peer) throws Exception {
        NetworkInterface fallback = null;
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!nic.isUp() || nic.isLoopback()) {
                continue;
            }
            for (InterfaceAddress ia : nic.getInterfaceAddresses()) {
                if (!(ia.getAddress() instanceof Inet4Address local)) {
                    continue;
                }
                if (fallback == null) {
                    fallback = nic;
                }
                if (peer instanceof Inet4Address p && sameSubnet(local, p, ia.getNetworkPrefixLength())) {
                    return nic;
                }
            }
        }
        return fallback;
    }

    private static Inet4Address ipv4Of(NetworkInterface nic) {
        if (nic == null) {
            return null;
        }
        for (InetAddress addr : Collections.list(nic.getInetAddresses())) {
            if (addr instanceof Inet4Address ipv4) {
                return ipv4;
            }
        }
        return null;
    }

    private static boolean sameSubnet(Inet4Address a, Inet4Address b, int prefix) {
        if (prefix < 0 || prefix > 32) {
            return false;
        }
        int mask = prefix == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - prefix));
        return (toUnsignedInt(a.getAddress()) & mask) == (toUnsignedInt(b.getAddress()) & mask);
    }

    /** Big-endian unsigned interpretation of up to 4 bytes. */
    private static int toUnsignedInt(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }

    @Override
    public void close() {
        running = false;
        if (socket != null) {
            socket.close();
        }
    }
}
