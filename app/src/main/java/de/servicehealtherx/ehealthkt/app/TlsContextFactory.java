package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtCardIdentity;
import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtKeyStore;
import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtNoneWithEcdsaSignatureSpi;
import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtPkcs1SignatureSpi;
import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtPssSignatureSpi;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import java.security.KeyStore;
import java.util.List;

/**
 * Builds the Netty {@link SslContext} for the SICCT TLS server. The terminal presents its SM-KT
 * certificate as the TLS server certificate. The JDK JSSE provider handles both the RSA and the
 * EC (secp256r1) software identities; see {@link SoftwareTerminalIdentity} for why the software EC
 * identity uses secp256r1 rather than a Brainpool curve.
 *
 * <p>For a real gSMC-KT ({@link #forCardIdentity}) the SM-KT certificate is a Brainpool
 * (brainpoolP256r1) certificate and the private key lives on the card. The BouncyCastle JSSE
 * provider is used together with {@code jdk.tls.namedGroups} so the Brainpool curve negotiates over
 * TLS 1.2, and card-backed {@code Signature} implementations route the handshake signing to the card
 * via PSO Compute Digital Signature. This mirrors the CardLink {@code SICCTTLSServer}.
 *
 * <p>The client (Konnektor) certificate is validated at the application layer
 * ({@link de.servicehealtherx.ehealthkt.terminal.KonnektorCertValidator}) in software mode; for a
 * real card the supplied {@code clientTrustManager} (gematik TUC_PKI_018) validates it at the TLS
 * layer.
 */
public final class TlsContextFactory {

    /**
     * Curves the eHealth-KT may negotiate for ECDHE. Includes the Brainpool curves a real gSMC-KT
     * uses (A_17089-01); these are not enabled by default in the JSSE providers, so they must be
     * named explicitly before the TLS context is created.
     */
    private static final String NAMED_GROUPS = "brainpoolP256r1,brainpoolP384r1,secp256r1,secp384r1";

    private TlsContextFactory() {
    }

    /**
     * Cipher suites the SICCT TLS server offers. ECDSA suites are negotiated when the SM-KT presents
     * an EC certificate, RSA suites when it presents an RSA certificate; the JSSE provider selects the
     * subset compatible with the server key, so listing both kinds is safe regardless of key type.
     * All four require TLS 1.2.
     */
    private static final List<String> CIPHER_SUITES = List.of(
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

    public static SslContext forSoftwareIdentity(SoftwareTerminalIdentity identity) throws Exception {
        return SslContextBuilder
                .forServer(identity.getPrivateKey(), identity.getCertificate())
                .clientAuth(ClientAuth.REQUIRE)
                .protocols("TLSv1.2")
                .ciphers(CIPHER_SUITES, SupportedCipherSuiteFilter.INSTANCE)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
    }

    /**
     * Build the TLS context for a real gSMC-KT: present the card's SM-KT certificate and sign the
     * handshake on the card. The BouncyCastle JSSE provider is configured with card-backed
     * {@code Signature} overrides so the JSSE handshake delegates signing to the gSMC-KT.
     *
     * @param card              the connected gSMC-KT identity (its key never leaves the card)
     * @param clientTrustManager validates the Konnektor's client certificate, or {@code null} to
     *                           accept any client chain (capturing the key for pairing in software)
     */
    public static SslContext forCardIdentity(GsmcKtCardIdentity card, TrustManager clientTrustManager)
            throws Exception {
        // Brainpool curves must be enabled before the TLS context is created (A_17089-01).
        System.setProperty("jdk.tls.namedGroups", NAMED_GROUPS);

        // A dedicated BouncyCastle provider whose ECDSA/RSA Signature services are replaced by the
        // card-backed SPIs; the BCJSSE provider performs all handshake crypto through it.
        BouncyCastleProvider cryptoProvider = new BouncyCastleProvider();
        cryptoProvider.put("Signature.NoneWithECDSA", GsmcKtNoneWithEcdsaSignatureSpi.class.getName());
        cryptoProvider.put("Signature.NoneWithRSA", GsmcKtPkcs1SignatureSpi.class.getName());
        cryptoProvider.put("Signature.SHA256withRSA", GsmcKtPkcs1SignatureSpi.class.getName());
        cryptoProvider.put("Signature.SHA256WITHRSAANDMGF1", GsmcKtPssSignatureSpi.class.getName());
        cryptoProvider.put("Signature.RSASSA-PSS", GsmcKtPssSignatureSpi.class.getName());

        BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider(false, cryptoProvider);

        KeyStore cardKeyStore = GsmcKtKeyStore.of(card);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", jsseProvider);
        kmf.init(cardKeyStore, new char[0]);

        SslContextBuilder builder = SslContextBuilder
                .forServer(kmf)
                .sslProvider(SslProvider.JDK)
                .sslContextProvider(jsseProvider)
                .protocols("TLSv1.2")
                .ciphers(CIPHER_SUITES, SupportedCipherSuiteFilter.INSTANCE)
                .clientAuth(ClientAuth.REQUIRE);
        if (clientTrustManager != null) {
            builder.trustManager(clientTrustManager);
        } else {
            builder.trustManager(InsecureTrustManagerFactory.INSTANCE);
        }
        return builder.build();
    }
}
