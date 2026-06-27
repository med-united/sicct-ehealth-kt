package de.servicehealtherx.ehealthkt.app.jmx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.management.remote.MBeanServerForwarder;
import javax.security.auth.Subject;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.EnumSet;
import java.util.Set;

/**
 * An {@link MBeanServerForwarder} that enforces {@link CtRole}-based access to the eHealth-KT
 * management MBean. It sits between the authenticated JMX connector and the real MBean server and
 * checks the authenticated {@link Subject}'s roles before each operation on the managed bean:
 *
 * <ul>
 *   <li>destructive administration (pairing-block removal, clearing, restart, factory reset)
 *       requires {@link CtRole#CT_ADMIN};</li>
 *   <li>every other operation/attribute on the managed bean requires any authenticated role
 *       ({@link CtRole#CT_CONTROL} or {@link CtRole#CT_ADMIN});</li>
 *   <li>access to other (e.g. platform) MBeans is left to the connector's own authentication.</li>
 * </ul>
 */
public final class CtRoleAccessForwarder {

    private static final Logger log = LoggerFactory.getLogger(CtRoleAccessForwarder.class);

    /** Operations on the managed bean that require CT_ADMIN. */
    public static final Set<String> ADMIN_ONLY_OPERATIONS = Set.of(
            "removePairingBlock",
            "removePairingBlockByKey",
            "clearPairingBlocks",
            "restart",
            "restartWithFactoryDefaults");

    private CtRoleAccessForwarder() {
    }

    /** Create a forwarder guarding the given managed object name. */
    public static MBeanServerForwarder create(ObjectName managed) {
        return (MBeanServerForwarder) Proxy.newProxyInstance(
                CtRoleAccessForwarder.class.getClassLoader(),
                new Class<?>[]{MBeanServerForwarder.class},
                new Handler(managed));
    }

    private static final class Handler implements InvocationHandler {

        private final ObjectName managed;
        private volatile MBeanServer target;

        Handler(ObjectName managed) {
            this.managed = managed;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "getMBeanServer" -> {
                    return target;
                }
                case "setMBeanServer" -> {
                    target = (MBeanServer) args[0];
                    return null;
                }
                case "invoke" -> enforceOperation((ObjectName) args[0], (String) args[1]);
                case "getAttribute", "getAttributes" -> enforce((ObjectName) args[0], CtRole.CT_CONTROL, "read");
                case "setAttribute", "setAttributes" -> enforce((ObjectName) args[0], CtRole.CT_ADMIN, "write");
                default -> { /* createMBean, queryNames, register listeners, … — no role gate */ }
            }
            try {
                return method.invoke(target, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        }

        private void enforceOperation(ObjectName name, String operation) {
            if (!managed.equals(name)) {
                return;
            }
            CtRole required = ADMIN_ONLY_OPERATIONS.contains(operation) ? CtRole.CT_ADMIN : CtRole.CT_CONTROL;
            requireRole(required, "operation " + operation);
        }

        private void enforce(ObjectName name, CtRole required, String what) {
            if (managed.equals(name)) {
                requireRole(required, what);
            }
        }

        private void requireRole(CtRole required, String what) {
            Set<CtRole> roles = currentRoles();
            // CT_ADMIN implicitly grants CT_CONTROL.
            boolean granted = roles.contains(required)
                    || (required == CtRole.CT_CONTROL && roles.contains(CtRole.CT_ADMIN));
            if (!granted) {
                log.warn("Denied JMX {} on {}: requires {}, caller has {}", what, managed, required, roles);
                throw new SecurityException("Access to " + what + " requires role " + required);
            }
        }
    }

    /** Roles of the currently authenticated JMX subject (empty if none). */
    @SuppressWarnings({"removal", "deprecation"})
    static Set<CtRole> currentRoles() {
        Subject subject = Subject.current();
        if (subject == null) {
            try {
                subject = Subject.getSubject(java.security.AccessController.getContext());
            } catch (Throwable ignored) {
                // Subject.getSubject is unsupported without a security manager on some JDKs.
            }
        }
        Set<CtRole> roles = EnumSet.noneOf(CtRole.class);
        if (subject != null) {
            for (CtRolePrincipal principal : subject.getPrincipals(CtRolePrincipal.class)) {
                roles.add(principal.role());
            }
        }
        return roles;
    }
}
