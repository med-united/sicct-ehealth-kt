package de.servicehealtherx.ehealthkt.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Firmware update capability (gemSpec_KT 2.4.1, TIP1-A_2965). Stubbed for the functional reference
 * implementation: a production terminal supports push (KSR/LAN) and pull update variants with
 * cryptographically verified images and configuration retention across updates.
 */
public interface FirmwareUpdateService {

    /** Trigger a manufacturer-specific firmware update; returns true if an update was applied. */
    boolean checkForUpdate();

    static FirmwareUpdateService noop() {
        Logger log = LoggerFactory.getLogger(FirmwareUpdateService.class);
        return () -> {
            log.info("Firmware update check: no update mechanism configured (stub)");
            return false;
        };
    }
}
