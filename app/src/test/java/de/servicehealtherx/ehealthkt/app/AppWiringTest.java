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
        new CommandLine(app).parseArgs("--port", "0", "--ui", "HEADLESS",
                "--terminal-name", "KT-1", "--no-discovery", "--tsl-production");
        assertThat(app.port).isZero();
        assertThat(app.uiKind).isEqualTo(EhealthKtApplication.UiKind.HEADLESS);
        assertThat(app.terminalName).isEqualTo("KT-1");
        assertThat(app.noDiscovery).isTrue();
        assertThat(app.tslProduction).isTrue();
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
