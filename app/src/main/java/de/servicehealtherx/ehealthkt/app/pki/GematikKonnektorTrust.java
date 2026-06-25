package de.servicehealtherx.ehealthkt.app.pki;

import de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.commons.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.utils.CertReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds the {@link X509TrustManager} that validates the Konnektor's TLS client certificate against
 * the gematik TI PKI using TUC_PKI_018. Mirrors the {@code crypto-lib} {@code TrustManagerProducer}:
 * a {@link TucPki018Verifier} is configured from the TSL, and the TSP CA certificates are exposed as
 * the accepted issuers.
 */
public final class GematikKonnektorTrust {

    private static final Logger log = LoggerFactory.getLogger(GematikKonnektorTrust.class);

    /** Product type reported by the verifier (used for OCSP requests / diagnostics). */
    private static final String PRODUCT_TYPE = "eHealth-KT";

    private GematikKonnektorTrust() {
    }

    /**
     * Build a client-certificate trust manager from an already-refreshed {@link TslDownloader}.
     *
     * <p>{@link CertificateProfile#CERT_PROFILE_ANY} is used because no dedicated profile exists for
     * the C.SMC-KT/Konnektor authentication certificate types; chain, validity and OCSP status are
     * still enforced. OCSP failures are tolerated so a transient responder outage does not block the
     * SICCT connection.
     */
    public static X509TrustManager clientTrustManager(TslDownloader tslDownloader) {
        List<TspService> tspServiceList = tslDownloader.getTspServiceList();
        if (tspServiceList == null) {
            throw new IllegalStateException("TSL not loaded; call TslDownloader.refresh() first");
        }

        TucPki018Verifier verifier = TucPki018Verifier.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .ocspTimeoutSeconds(14)
                .certificateProfiles(List.of(CertificateProfile.CERT_PROFILE_ANY))
                .tolerateOcspFailure(true)
                .build();

        X509Certificate[] acceptedIssuers = tspServiceList.stream()
                .flatMap(tsp -> tsp.getTspServiceType().getServiceInformation()
                        .getServiceDigitalIdentity().getDigitalId().stream())
                .filter(id -> id.getX509Certificate() != null)
                .map(id -> {
                    try {
                        return CertReader.readX509(PRODUCT_TYPE, id.getX509Certificate());
                    } catch (Exception e) {
                        log.warn("Could not read a TSP service issuer certificate", e);
                        return null;
                    }
                })
                .filter(cert -> cert != null)
                .toArray(X509Certificate[]::new);

        log.info("Built TUC_PKI_018 Konnektor trust manager with {} accepted issuers", acceptedIssuers.length);
        return new TucPki18VerifierTrustManager(verifier, false, acceptedIssuers);
    }
}
