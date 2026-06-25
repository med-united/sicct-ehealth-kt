package de.servicehealtherx.ehealthkt.app.pki;

import de.gematik.pki.gemlibpki.commons.certificate.TucPki018Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * An {@link X509TrustManager} that validates a peer certificate with gematik's TUC_PKI_018 checks
 * (chain to a TSL trust anchor, certificate profile, validity, and OCSP status) via a
 * {@link TucPki018Verifier}.
 *
 * <p>The eHealth-KT is the TLS <em>server</em>, so the Konnektor presents a <em>client</em>
 * certificate; this trust manager therefore runs the TUC_PKI_018 checks in
 * {@link #checkClientTrusted}. {@link #checkServerTrusted} is unused (the eHealth-KT never acts as a
 * TLS client here). Ported from the {@code crypto-lib} {@code TucPki18VerifierTrustManager}.
 */
public class TucPki18VerifierTrustManager implements X509TrustManager {

    private static final Logger log = LoggerFactory.getLogger(TucPki18VerifierTrustManager.class);

    private final TucPki018Verifier verifier;
    private final boolean checkServer;
    private final X509Certificate[] acceptedIssuers;

    public TucPki18VerifierTrustManager(TucPki018Verifier verifier, boolean checkServer,
                                        X509Certificate[] acceptedIssuers) {
        this.verifier = verifier;
        this.checkServer = checkServer;
        this.acceptedIssuers = acceptedIssuers;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (checkServer) {
            throw new CertificateException("Client certificate validation is disabled");
        }
        validate(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (!checkServer) {
            throw new CertificateException("Server certificate validation is disabled");
        }
        validate(chain);
    }

    private void validate(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("No peer certificate presented");
        }
        try {
            verifier.performTucPki018Checks(chain[0]);
            log.debug("TUC_PKI_018 validation passed for {}", chain[0].getSubjectX500Principal());
        } catch (Exception e) {
            throw new CertificateException("TUC_PKI_018 validation failed for "
                    + chain[0].getSubjectX500Principal(), e);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return acceptedIssuers.clone();
    }
}
