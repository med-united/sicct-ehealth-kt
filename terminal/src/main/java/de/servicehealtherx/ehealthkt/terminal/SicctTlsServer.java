package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.sicct.codec.SicctEncoder;
import de.servicehealtherx.ehealthkt.sicct.codec.SicctFrameDecoder;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.timeout.IdleStateHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;

/**
 * The SICCT TLS server: listens on the configured port (default 4742), terminates mutual TLS and
 * runs the SICCT pipeline (frame codec, idle/keep-alive handling, command interpreter) per
 * connection. Refactored from the CardLink {@code SICCTTLSServer}.
 */
public class SicctTlsServer implements AutoCloseable {

    public static final int DEFAULT_PORT = 4742;

    private static final Logger log = LoggerFactory.getLogger(SicctTlsServer.class);

    private final int port;
    private final SslContext sslContext;
    private final Supplier<SicctCommandInterpreter> interpreterFactory;
    private final int readerIdleSeconds;
    private final int writerIdleSeconds;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private Channel serverChannel;

    public SicctTlsServer(int port, SslContext sslContext,
                          Supplier<SicctCommandInterpreter> interpreterFactory,
                          int readerIdleSeconds, int writerIdleSeconds) {
        this.port = port;
        this.sslContext = sslContext;
        this.interpreterFactory = interpreterFactory;
        this.readerIdleSeconds = readerIdleSeconds;
        this.writerIdleSeconds = writerIdleSeconds;
    }

    /** Start the server and block until the listen socket is bound. Returns the bound port. */
    public synchronized int start() throws InterruptedException {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_REUSEADDR, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast("ssl", sslContext.newHandler(ch.alloc()));
                        ch.pipeline().addLast("idle",
                                new IdleStateHandler(readerIdleSeconds, writerIdleSeconds, 0));
                        ch.pipeline().addLast("keepalive", new SicctKeepAliveHandler());
                        ch.pipeline().addLast("decoder", new SicctFrameDecoder());
                        ch.pipeline().addLast("encoder", new SicctEncoder());
                        ch.pipeline().addLast("interpreter", interpreterFactory.get());
                    }
                });
        serverChannel = bootstrap.bind(port).sync().channel();
        int boundPort = ((java.net.InetSocketAddress) serverChannel.localAddress()).getPort();
        log.info("SICCT eHealth-KT listening on port {}", boundPort);
        return boundPort;
    }

    @Override
    public synchronized void close() {
        if (serverChannel != null) {
            serverChannel.close().awaitUninterruptibly();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        log.info("SICCT eHealth-KT stopped");
    }
}
