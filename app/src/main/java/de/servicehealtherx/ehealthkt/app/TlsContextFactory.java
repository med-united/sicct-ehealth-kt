package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Builds the Netty {@link SslContext} for the SICCT TLS server. The terminal presents its SM-KT
 * certificate as the TLS server certificate. When the SM-KT key uses a Brainpool curve, the
 * BouncyCastle JSSE provider is used (the JDK provider does not support Brainpool in TLS).
 *
 * <p>The client (Konnektor) certificate is validated at the application layer
 * ({@link de.servicehealtherx.ehealthkt.terminal.KonnektorCertValidator}); here the TLS trust manager
 * accepts the presented chain so the public key can be captured for pairing.
 */
public final class TlsContextFactory {

    private TlsContextFactory() {
    }

    public static SslContext forSoftwareIdentity(SoftwareTerminalIdentity identity) throws Exception {
        SslContextBuilder builder = SslContextBuilder
                .forServer(identity.getPrivateKey(), identity.getCertificate())
                .clientAuth(ClientAuth.REQUIRE)
                .trustManager(InsecureTrustManagerFactory.INSTANCE);
        if (identity.getKeyType() == KeyType.EC) {
            // Brainpool curves require the BouncyCastle JSSE provider.
            builder.sslProvider(SslProvider.JDK)
                    .sslContextProvider(new BouncyCastleJsseProvider());
        }
        return builder.build();
    }
}
