package de.servicehealtherx.ehealthkt.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Terminal management interface (gemSpec_KT 2.4.5): administration, configuration and role-based
 * access (CT_ADMIN / CT_CONTROL). Stubbed for the functional reference implementation.
 */
public interface ManagementInterface {

    void start();

    void stop();

    static ManagementInterface noop() {
        Logger log = LoggerFactory.getLogger(ManagementInterface.class);
        return new ManagementInterface() {
            @Override
            public void start() {
                log.info("Management interface: disabled (stub)");
            }

            @Override
            public void stop() {
            }
        };
    }
}
