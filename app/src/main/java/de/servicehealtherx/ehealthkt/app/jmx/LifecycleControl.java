package de.servicehealtherx.ehealthkt.app.jmx;

/**
 * Abstraction over the terminal's process lifecycle so the JMX management interface can trigger a
 * restart without depending on how the restart is actually performed (process relaunch, supervisor
 * exit code, in-process re-wire, …). The application supplies the concrete implementation.
 */
public interface LifecycleControl {

    /**
     * Restart the terminal. Implementations typically return promptly (so the triggering JMX call
     * can complete) and perform the actual teardown/relaunch shortly afterwards.
     */
    void restart();
}
