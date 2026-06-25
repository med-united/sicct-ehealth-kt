package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.gsmckt.GsmcKtCardIdentity;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Hardware integration test for the gSMC-KT-backed TLS server: completes a real brainpoolP256r1
 * mutual-TLS handshake in which the card signs the handshake (PSO Compute Digital Signature) and
 * presents its SM-KT certificate as the TLS server certificate, exercising
 * {@link TlsContextFactory#forCardIdentity}.
 *
 * <p>Requires a physical gSMC-KT in a PC/SC reader. The test self-skips ({@code Assumptions}) when
 * no such card is found, so it is inert in CI. To target a specific reader, set
 * {@code -Dgsmckt.test.reader=<index>}; otherwise all readers are scanned.
 */
class CardTlsHandshakeIT {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void cardSignsBrainpoolMutualTlsHandshake() throws Exception {
        Card card = openGsmcKt();
        assumeTrue(card != null, "No gSMC-KT found in any PC/SC reader; skipping hardware TLS test");

        try {
            GsmcKtCardIdentity identity = new GsmcKtCardIdentity(card.getBasicChannel());
            assumeTrue(identity.getEcCertificate() != null, "Card has no ECC SM-KT certificate; skipping");

            // accept-all client trust here; the gematik TUC_PKI_018 path is wired separately.
            SslContext serverSsl = TlsContextFactory.forCardIdentity(identity, null);
            HandshakeResult result = runLoopback(serverSsl);

            assertThat(result.completed).as("mutual TLS handshake completed").isTrue();
            assertThat(result.cipherSuite).contains("ECDHE_ECDSA");
            // The client's peer certificate is the card's SM-KT certificate (server cert).
            assertThat(result.serverCertSubject)
                    .isEqualTo(identity.getEcCertificate().getSubjectX500Principal().getName());
            // The server received the client's certificate (mutual auth happened).
            assertThat(result.clientCertSubject).isEqualTo("CN=test-konnektor");
            assertThat(result.reply).isEqualTo("pong");
        } finally {
            card.disconnect(false);
        }
    }

    private record HandshakeResult(boolean completed, String cipherSuite, String serverCertSubject,
                                   String clientCertSubject, String reply) {
    }

    /** Run a localhost Netty loopback: card-backed server vs. a BouncyCastle TLS client. */
    private HandshakeResult runLoopback(SslContext serverSsl) throws Exception {
        AtomicReference<String> cipher = new AtomicReference<>("");
        AtomicReference<String> serverCert = new AtomicReference<>("");
        AtomicReference<String> clientCert = new AtomicReference<>("");
        AtomicReference<String> reply = new AtomicReference<>("");
        CountDownLatch done = new CountDownLatch(1);

        NioEventLoopGroup boss = new NioEventLoopGroup(1);
        NioEventLoopGroup workers = new NioEventLoopGroup();
        NioEventLoopGroup clientGroup = new NioEventLoopGroup();
        try {
            Channel server = new ServerBootstrap().group(boss, workers)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(serverSsl.newHandler(ch.alloc()));
                            ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
                                    var session = ctx.pipeline().get(SslHandler.class).engine().getSession();
                                    cipher.set(session.getCipherSuite());
                                    clientCert.set(((X509Certificate) session.getPeerCertificates()[0])
                                            .getSubjectX500Principal().getName());
                                    ctx.writeAndFlush(ctx.alloc().buffer().writeBytes("pong".getBytes(StandardCharsets.UTF_8)));
                                }
                            });
                        }
                    }).bind(new InetSocketAddress("127.0.0.1", 0)).sync().channel();
            int port = ((InetSocketAddress) server.localAddress()).getPort();

            SslContext clientSsl = clientContext();
            new Bootstrap().group(clientGroup).channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        protected void initChannel(SocketChannel ch) {
                            SslHandler ssl = clientSsl.newHandler(ch.alloc(), "127.0.0.1", port);
                            ch.pipeline().addLast(ssl);
                            ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                                public void channelActive(ChannelHandlerContext ctx) {
                                    ssl.handshakeFuture().addListener(f -> {
                                        if (f.isSuccess()) {
                                            serverCert.set(((X509Certificate) ssl.engine().getSession()
                                                    .getPeerCertificates()[0]).getSubjectX500Principal().getName());
                                            ctx.writeAndFlush(ctx.alloc().buffer()
                                                    .writeBytes("ping".getBytes(StandardCharsets.UTF_8)));
                                        } else {
                                            done.countDown();
                                        }
                                    });
                                }
                                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                                    reply.set(msg.toString(StandardCharsets.UTF_8));
                                    done.countDown();
                                }
                            });
                        }
                    }).connect("127.0.0.1", port).sync();

            boolean completed = done.await(15, TimeUnit.SECONDS) && !reply.get().isEmpty();
            return new HandshakeResult(completed, cipher.get(), serverCert.get(), clientCert.get(), reply.get());
        } finally {
            boss.shutdownGracefully();
            workers.shutdownGracefully();
            clientGroup.shutdownGracefully();
        }
    }

    /** A BouncyCastle TLS client (brainpool enabled via explicit BC crypto) with a self-signed cert. */
    private static SslContext clientContext() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        g.initialize(new ECNamedCurveGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        X500Name dn = new X500Name("CN=test-konnektor");
        long now = System.currentTimeMillis();
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                new JcaX509v3CertificateBuilder(dn, BigInteger.valueOf(now),
                        new Date(now - 86_400_000L), new Date(now + 86_400_000L), dn, kp.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(kp.getPrivate())));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("c", kp.getPrivate(), "x".toCharArray(), new X509Certificate[] {cert});

        BouncyCastleJsseProvider jsse = new BouncyCastleJsseProvider(false, new BouncyCastleProvider());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", jsse);
        kmf.init(ks, "x".toCharArray());
        return SslContextBuilder.forClient()
                .sslProvider(SslProvider.JDK)
                .sslContextProvider(jsse)
                .keyManager(kmf)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .protocols("TLSv1.2")
                .ciphers(List.of("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"))
                .build();
    }

    /** Scan PC/SC readers (or {@code -Dgsmckt.test.reader}) for a card exposing DF.KT; {@code null} if none. */
    private static Card openGsmcKt() {
        List<CardTerminal> terminals;
        try {
            terminals = TerminalFactory.getDefault().terminals().list();
        } catch (Exception e) {
            return null;
        }
        String fixed = System.getProperty("gsmckt.test.reader");
        for (int i = 0; i < terminals.size(); i++) {
            if (fixed != null && i != Integer.parseInt(fixed)) {
                continue;
            }
            try {
                CardTerminal t = terminals.get(i);
                if (!t.isCardPresent()) {
                    continue;
                }
                Card card = t.connect("T=1");
                // Probe: a gSMC-KT exposes DF.KT (AID D2 76 00 01 44 00).
                new GsmcKtCardIdentity(card.getBasicChannel());
                return card;
            } catch (Exception ignored) {
                // not a gSMC-KT in this reader
            }
        }
        return null;
    }
}
