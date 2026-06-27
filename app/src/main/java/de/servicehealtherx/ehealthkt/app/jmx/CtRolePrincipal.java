package de.servicehealtherx.ehealthkt.app.jmx;

import java.security.Principal;
import java.util.Objects;

/**
 * A {@link Principal} carrying a single {@link CtRole}. Added to the authenticated JMX
 * {@link javax.security.auth.Subject} so the access forwarder can enforce role-based access.
 */
public final class CtRolePrincipal implements Principal {

    private final CtRole role;

    public CtRolePrincipal(CtRole role) {
        this.role = Objects.requireNonNull(role, "role");
    }

    public CtRole role() {
        return role;
    }

    @Override
    public String getName() {
        return role.name();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof CtRolePrincipal other && role == other.role;
    }

    @Override
    public int hashCode() {
        return role.hashCode();
    }

    @Override
    public String toString() {
        return "CtRolePrincipal[" + role + "]";
    }
}
