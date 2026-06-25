package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.card.CardSlotManager;
import de.servicehealtherx.ehealthkt.card.SimulatedCardSlotBackend;
import de.servicehealtherx.ehealthkt.card.sim.ScriptedVirtualCard;
import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.PairingSignatures;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.MessageType;
import de.servicehealtherx.ehealthkt.sicct.SicctMessage;
import de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full hardware-free end-to-end test: an in-process "Konnektor" connects over mutual TLS and drives
 * the eHealth-KT through pairing, card access and PIN verification against a simulated eGK.
 */
class SicctEndToEndTest {

    private static final byte[] SHARED_SECRET = Hex.toBytes("000102030405060708090A0B0C0D0E0F");

    private SoftwareTerminalIdentity serverIdentity;
    private SicctTlsServer server;
    private NioEventLoopGroup clientGroup;
    private Channel clientChannel;
    private final BlockingQueue<SicctMessage> responses = new LinkedBlockingQueue<>();
    private int port;
    private PublicKey serverPublicKey;

    @BeforeEach
    void setUp() throws Exception {
        serverIdentity = new SoftwareTerminalIdentity(KeyType.RSA);
        InMemoryPairingStore pairingStore = new InMemoryPairingStore();

        SimulatedCardSlotBackend backend = new SimulatedCardSlotBackend(3);
        backend.simulatedSlot(2).insert(ScriptedVirtualCard.egk());
        CardSlotManager cards = new CardSlotManager(backend);
        HeadlessUi ui = HeadlessUi.withPin("123456");

        EhealthTerminalAuthenticate authenticate =
                new EhealthTerminalAuthenticate(serverIdentity, pairingStore, ui);

        SslContext serverSsl = SslContextBuilder
                .forServer(serverIdentity.getPrivateKey(), serverIdentity.getCertificate())
                .clientAuth(ClientAuth.REQUIRE)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        server = new SicctTlsServer(0, serverSsl,
                () -> new SicctCommandInterpreter(cards, ui, pairingStore, authenticate,
                        KonnektorCertValidator.acceptAll(), new SicctSessionRegistry()),
                119, 30);
        port = server.start();

        connectClient();
    }

    private void connectClient() throws Exception {
        // The "Konnektor" client uses its own self-signed identity as TLS client certificate.
        SoftwareTerminalIdentity clientId = new SoftwareTerminalIdentity(KeyType.RSA);
        SslContext clientSsl = SslContextBuilder.forClient()
                .keyManager(clientId.getPrivateKey(), clientId.getCertificate())
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        clientGroup = new NioEventLoopGroup(1);
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(clientGroup)
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(clientSsl.newHandler(ch.alloc(), "localhost", port));
                        ch.pipeline().addLast(new de.servicehealtherx.ehealthkt.sicct.codec.SicctFrameDecoder());
                        ch.pipeline().addLast(new de.servicehealtherx.ehealthkt.sicct.codec.SicctEncoder());
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<SicctMessage>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, SicctMessage msg) {
                                if (msg.type() == MessageType.RESPONSE) {
                                    responses.add(msg);
                                }
                            }
                        });
                    }
                });
        clientChannel = bootstrap.connect("localhost", port).sync().channel();
        // capture the server certificate public key from the TLS session
        io.netty.handler.ssl.SslHandler ssl = clientChannel.pipeline().get(io.netty.handler.ssl.SslHandler.class);
        ssl.handshakeFuture().sync();
        serverPublicKey = ssl.engine().getSession().getPeerCertificates()[0].getPublicKey();
    }

    @AfterEach
    void tearDown() {
        if (clientChannel != null) clientChannel.close().awaitUninterruptibly();
        if (clientGroup != null) clientGroup.shutdownGracefully();
        if (server != null) server.close();
    }

    private SicctMessage roundTrip(short slot, short seq, String apduHex) throws Exception {
        responses.clear();
        clientChannel.writeAndFlush(SicctMessage.of(MessageType.COMMAND, slot, seq, Hex.toBytes(apduHex)));
        SicctMessage response = responses.poll(5, TimeUnit.SECONDS);
        assertThat(response).as("response for %s", apduHex).isNotNull();
        return response;
    }

    @Test
    void fullPairingCardAccessAndPinFlow() throws Exception {
        // 1) INIT CT SESSION
        assertThat(Hex.toHex(roundTrip((short) 0, (short) 1, "80280000").getBody())).isEqualTo("9000");

        // 2) EHEALTH TERMINAL AUTHENTICATE CREATE: D4 10 <secret> 50 09 "Konnektor"
        byte[] label = "Konnektor".getBytes();
        String createData = "D410" + Hex.toHex(SHARED_SECRET) + "50" + Hex.toHex((byte) label.length) + Hex.toHex(label);
        String createApdu = "81AA0001" + Hex.toHex((byte) (createData.length() / 2)) + createData;
        SicctMessage createResp = roundTrip((short) 0, (short) 2, createApdu);
        // Response APDU = 256-byte signature + SW 9000.
        byte[] createBody = createResp.getBody();
        assertThat(createBody).hasSize(258);
        assertThat(Hex.toHex(createBody)).endsWith("9000");
        byte[] signature = java.util.Arrays.copyOf(createBody, 256);
        assertThat(PairingSignatures.verify(serverPublicKey, SHARED_SECRET, signature)).isTrue();

        // 3) EHEALTH TERMINAL AUTHENTICATE VALIDATE: D5 10 <challenge>
        byte[] challenge = Hex.toBytes("0F0E0D0C0B0A09080706050403020100");
        String validateData = "D510" + Hex.toHex(challenge);
        String validateApdu = "81AA0002" + Hex.toHex((byte) (validateData.length() / 2)) + validateData;
        byte[] hashResp = roundTrip((short) 0, (short) 3, validateApdu).getBody();
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(Hex.concat(challenge, SHARED_SECRET));
        // Response APDU = 32-byte SHA-256 hash + SW 9000.
        assertThat(Hex.toHex(hashResp)).isEqualTo(Hex.toHex(expected) + "9000");

        // 4) REQUEST ICC for slot 2 (now paired) -> ATR + 9000
        byte[] requestIcc = roundTrip((short) 0, (short) 4, "801202F1").getBody();
        assertThat(Hex.toHex(requestIcc)).endsWith("9000");

        // 4a) RESET ICC for slot 2 -> 9001 (asynchronous/processor chipcard presented)
        assertThat(Hex.toHex(roundTrip((short) 0, (short) 40, "801102F1").getBody())).isEqualTo("9001");

        // 4b) RESET CT addressing the terminal (FU 0) -> 9000 (no chipcard type to qualify)
        assertThat(Hex.toHex(roundTrip((short) 0, (short) 41, "80110000").getBody())).isEqualTo("9000");

        // 5) SELECT eGK application on slot 2 (ISO APDU addressed to the slot)
        assertThat(Hex.toHex(roundTrip((short) 2, (short) 5, "00A4040007D2760001448000").getBody()))
                .isEqualTo("9000");

        // 6) PERFORM VERIFICATION on slot 2 -> headless UI supplies PIN 123456 -> 9000
        assertThat(Hex.toHex(roundTrip((short) 0, (short) 6, "801802F1").getBody())).isEqualTo("9000");

        // 7) CLOSE CT SESSION
        assertThat(Hex.toHex(roundTrip((short) 0, (short) 7, "80290000").getBody())).isEqualTo("9000");
    }

    @Test
    void commandsBeforePairingAreRejected() throws Exception {
        // REQUEST ICC without pairing must be rejected with 6901
        assertThat(Hex.toHex(roundTrip((short) 0, (short) 1, "801202F1").getBody())).isEqualTo("6901");
    }
}
