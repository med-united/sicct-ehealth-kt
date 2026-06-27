package de.servicehealtherx.ehealthkt.app.jmx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * A {@link JMXAuthenticator} that validates {@code String[]{user, password}} credentials against a
 * configured set of accounts and returns a {@link Subject} carrying the user's {@link CtRole}s.
 */
public final class CtRoleAuthenticator implements JMXAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(CtRoleAuthenticator.class);

    /** A configured management account. */
    public record Account(String password, Set<CtRole> roles) {
        public Account {
            roles = roles.isEmpty() ? EnumSet.noneOf(CtRole.class) : EnumSet.copyOf(roles);
        }
    }

    private final Map<String, Account> accounts;

    public CtRoleAuthenticator(Map<String, Account> accounts) {
        if (accounts.isEmpty()) {
            throw new IllegalArgumentException("No JMX accounts configured");
        }
        this.accounts = Map.copyOf(accounts);
    }

    /**
     * Load accounts from a properties file. Each entry maps a username to a comma-separated list
     * whose first element is the password and whose remaining elements are roles, e.g.
     * <pre>
     *   admin    = s3cret  , CT_ADMIN
     *   operator = pin0000 , CT_CONTROL
     * </pre>
     */
    public static CtRoleAuthenticator fromUsersFile(Path file) {
        Properties props = new Properties();
        try {
            props.load(Files.newBufferedReader(file, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read JMX users file " + file, e);
        }
        Map<String, Account> accounts = new LinkedHashMap<>();
        for (String user : props.stringPropertyNames()) {
            String[] parts = props.getProperty(user).split(",");
            if (parts.length < 2) {
                throw new IllegalArgumentException("JMX users file entry '" + user
                        + "' must be 'password, ROLE[, ROLE...]'");
            }
            String password = parts[0].trim();
            Set<CtRole> roles = EnumSet.noneOf(CtRole.class);
            for (int i = 1; i < parts.length; i++) {
                roles.add(CtRole.valueOf(parts[i].trim()));
            }
            accounts.put(user.trim(), new Account(password, roles));
        }
        log.info("Loaded {} JMX management account(s) from {}", accounts.size(), file);
        return new CtRoleAuthenticator(accounts);
    }

    @Override
    public Subject authenticate(Object credentials) {
        if (!(credentials instanceof String[] creds) || creds.length != 2) {
            throw new SecurityException("Credentials must be a String[]{username, password}");
        }
        String user = creds[0];
        String password = creds[1];
        Account account = user == null ? null : accounts.get(user);
        // Always run the comparison (even for unknown users) to avoid leaking which users exist.
        String expected = account == null ? "" : account.password();
        if (!constantTimeEquals(expected, password) || account == null) {
            log.warn("Rejected JMX authentication for user '{}'", user);
            throw new SecurityException("Invalid credentials");
        }
        Set<Principal> principals = new HashSet<>();
        principals.add(new JMXPrincipal(user));
        for (CtRole role : account.roles()) {
            principals.add(new CtRolePrincipal(role));
        }
        log.info("Authenticated JMX user '{}' with roles {}", user, account.roles());
        return new Subject(true, principals, Set.of(), Set.of());
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
