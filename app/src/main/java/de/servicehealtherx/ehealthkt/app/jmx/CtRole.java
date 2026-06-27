package de.servicehealtherx.ehealthkt.app.jmx;

/**
 * Card-terminal management roles per gemSpec_KT (2.4.5, role-based access to the management
 * interface).
 *
 * <ul>
 *   <li>{@link #CT_ADMIN} — administration: configuration changes, pairing-block removal and
 *       restarts/factory reset. Implicitly holds all {@link #CT_CONTROL} rights as well.</li>
 *   <li>{@link #CT_CONTROL} — operational control: read state, list pairings, confirm pairing and
 *       enter PINs, but no destructive administration.</li>
 * </ul>
 */
public enum CtRole {
    CT_ADMIN,
    CT_CONTROL
}
