package de.servicehealtherx.ehealthkt.app;

import static org.assertj.core.api.Assertions.assertThat;

import de.servicehealtherx.ehealthkt.sicct.Hex;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ServiceDiscoveryServerTest {

    /**
     * The A1 discovery response must follow SICCT v1.2.3 §6.2.3 and match the byte layout the
     * reference Konnektor expects: A1 { 80 version, 81 ip, 83 mac, 84 host, 82 port, A3 security }.
     */
    @Test
    void buildsSpecCompliantA1Response() throws Exception {
        Inet4Address ip = (Inet4Address) InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 168, 1, (byte) 153});
        byte[] mac = Hex.toBytes("4438e815d7cc");

        byte[] response = ServiceDiscoveryServer.buildResponse(ip, mac, "eHealth-KT", 4742);

        assertThat(Hex.toHex(response)).isEqualToIgnoringCase(
                "a127"                       // A1, length 0x27
                + "80020114"                 // 80 version 1.20
                + "8104c0a80199"             // 81 ip 192.168.1.153
                + "83064438e815d7cc"         // 83 mac
                + "840a6548" + "65616c74682d4b54" // 84 host "eHealth-KT"
                + "82021286"                 // 82 port 4742
                + "a3038a0130");             // A3 security: TLS 1.2
    }

    @Test
    void hostNameIsSanitisedAndTruncated() throws Exception {
        Inet4Address ip = (Inet4Address) InetAddress.getByAddress(new byte[] {10, 0, 0, 1});
        byte[] response = ServiceDiscoveryServer.buildResponse(
                ip, new byte[6], "terminal.with.a.very.long.dotted.name.here", 4742);

        // host tag 84, length 0x1f (31, the SICCT cap), ASCII payload with dots replaced by hyphens
        String hex = Hex.toHex(response).toLowerCase();
        int hostStart = hex.indexOf("841f") + 4;
        String host = new String(Hex.toBytes(hex.substring(hostStart, hostStart + 31 * 2)),
                StandardCharsets.US_ASCII);
        assertThat(host).isEqualTo("terminal-with-a-very-long-dotte").doesNotContain(".");
    }
}
