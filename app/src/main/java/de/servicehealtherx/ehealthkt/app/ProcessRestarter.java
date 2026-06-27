package de.servicehealtherx.ehealthkt.app;

import de.servicehealtherx.ehealthkt.app.jmx.LifecycleControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Restarts the eHealth-KT by relaunching the JVM with the same command line. The relaunch runs on a
 * short-delay daemon thread so the triggering JMX call can return to the client first; it then tears
 * down the current runtime (releasing the SICCT port and PC/SC readers), spawns the replacement
 * process and {@linkplain Runtime#halt(int) halts} this one (skipping the shutdown hook, since
 * teardown has already run).
 */
final class ProcessRestarter implements LifecycleControl {

    private static final Logger log = LoggerFactory.getLogger(ProcessRestarter.class);

    private final Runnable teardown;
    private final long delayMillis;

    ProcessRestarter(Runnable teardown) {
        this(teardown, 500);
    }

    ProcessRestarter(Runnable teardown, long delayMillis) {
        this.teardown = teardown;
        this.delayMillis = delayMillis;
    }

    @Override
    public void restart() {
        Thread t = new Thread(this::relaunch, "ehealth-kt-restart");
        t.setDaemon(true);
        t.start();
    }

    private void relaunch() {
        try {
            Thread.sleep(delayMillis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        List<String> command = currentCommand();
        log.warn("Restarting eHealth-KT: {}", String.join(" ", command));
        try {
            teardown.run();
        } catch (RuntimeException e) {
            log.warn("Teardown before restart failed; relaunching anyway", e);
        }
        try {
            new ProcessBuilder(command).inheritIO().start();
        } catch (IOException e) {
            log.error("Could not relaunch eHealth-KT process; aborting restart", e);
            return;
        }
        // Skip the JVM shutdown hook: teardown already ran, and the replacement process is live.
        Runtime.getRuntime().halt(0);
    }

    /**
     * Reconstruct the command line that started this JVM. Prefers the OS-reported command/arguments
     * (reliable on Linux), falling back to {@code java.home}, the JVM input arguments and
     * {@code sun.java.command}.
     */
    static List<String> currentCommand() {
        ProcessHandle.Info info = ProcessHandle.current().info();
        if (info.command().isPresent()) {
            List<String> command = new ArrayList<>();
            command.add(info.command().get());
            info.arguments().ifPresent(args -> command.addAll(List.of(args)));
            return command;
        }
        return reconstructCommand();
    }

    private static List<String> reconstructCommand() {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.addAll(ManagementFactory.getRuntimeMXBean().getInputArguments());

        String sunCommand = System.getProperty("sun.java.command", "");
        String[] parts = sunCommand.isBlank() ? new String[0] : sunCommand.split(" ");
        String launched = parts.length > 0 ? parts[0] : "";
        if (launched.endsWith(".jar")) {
            command.add("-jar");
            command.add(launched);
        } else {
            command.add("-cp");
            command.add(System.getProperty("java.class.path"));
            if (!launched.isEmpty()) {
                command.add(launched);
            }
        }
        for (int i = 1; i < parts.length; i++) {
            command.add(parts[i]);
        }
        return command;
    }
}
