package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import io.netty.handler.ssl.SslContext;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

class AppWiringTest {

    @Test
    void parsesCliOptions() {
        EhealthKtApplication app = new EhealthKtApplication();
        new CommandLine(app).parseArgs("--mode", "SIM", "--port", "0", "--key-type", "EC",
                "--ui", "HEADLESS", "--egk-slot", "3", "--no-discovery");
        assertThat(app.mode).isEqualTo(EhealthKtApplication.Mode.SIM);
        assertThat(app.port).isZero();
        assertThat(app.keyType).isEqualTo(KeyType.EC);
        assertThat(app.egkSlot).isEqualTo(3);
        assertThat(app.noDiscovery).isTrue();
    }

    @Test
    void buildsRsaTlsContext() throws Exception {
        SslContext ctx = TlsContextFactory.forSoftwareIdentity(new SoftwareTerminalIdentity(KeyType.RSA));
        assertThat(ctx).isNotNull();
        assertThat(ctx.isServer()).isTrue();
    }

    @Test
    void buildsBrainpoolEcTlsContextViaBouncyCastle() throws Exception {
        SslContext ctx = TlsContextFactory.forSoftwareIdentity(new SoftwareTerminalIdentity(KeyType.EC));
        assertThat(ctx).isNotNull();
        assertThat(ctx.isServer()).isTrue();
    }
}
