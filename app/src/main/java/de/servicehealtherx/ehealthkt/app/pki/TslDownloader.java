package de.servicehealtherx.ehealthkt.app.pki;

import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TslReader;
import de.gematik.pki.gemlibpki.commons.tsl.TslValidator;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.utils.CertReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.URI;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Downloads and caches the gematik TI Trust-service Status List (TSL) and exposes its TSP services
 * for TUC_PKI_018 certificate validation (see
 * <a href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_PKI/latest/#8.3.1.1">gemSpec_PKI §8.3.1.1</a>).
 *
 * <p>The signed TSL is fetched over HTTP, its signature checked against the bundled TSL-signer CA
 * (RU/test: {@code C.GEM.TSL-CA28}, PU/production: {@code C.GEM.TSL-CA3}), then cached on disk and
 * refreshed when older than two weeks. De-Quarkus-ified port of the {@code crypto-lib} TslDownloader.
 */
public final class TslDownloader {

    private static final Logger log = LoggerFactory.getLogger(TslDownloader.class);

    private static final String TSL_URL_PU = "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.xml";
    private static final String TSL_URL_RU = "http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.xml";
    private static final String SIGNER_CERT_PU = "/tsl-signer-certs/C.GEM.TSL-CA3.der";
    private static final String SIGNER_CERT_RU = "/tsl-signer-certs/C.GEM.TSL-CA28.der";
    private static final long MAX_AGE_MILLIS = 14L * 24 * 60 * 60 * 1000; // two weeks

    private final boolean production;
    private final Path cacheDir;
    private volatile List<TspService> tspServiceList;

    /**
     * @param production {@code true} to use the production (PU) TSL, {@code false} for the
     *                   reference/test (RU) TSL — use RU for gematik {@code TEST-ONLY} cards.
     * @param cacheDir   directory in which the downloaded TSL is cached.
     */
    public TslDownloader(boolean production, Path cacheDir) {
        this.production = production;
        this.cacheDir = cacheDir;
    }

    /** (Re-)download the TSL if the cache is missing or stale, then parse its TSP services. */
    public synchronized void refresh() {
        try {
            Files.createDirectories(cacheDir);
            String tslUrl = production ? TSL_URL_PU : TSL_URL_RU;
            String fileName = tslUrl.substring(tslUrl.lastIndexOf('/') + 1);
            Path tsl = cacheDir.resolve(fileName);

            boolean stale = !Files.exists(tsl)
                    || (System.currentTimeMillis() - Files.getLastModifiedTime(tsl).toMillis()) > MAX_AGE_MILLIS;
            if (stale) {
                log.info("Downloading TSL from {}", tslUrl);
                URLConnection connection = new URI(tslUrl).toURL().openConnection();
                connection.connect();
                byte[] tslFromUrl;
                try (InputStream in = connection.getInputStream()) {
                    tslFromUrl = in.readAllBytes();
                }
                if (!validateTsl(tslFromUrl)) {
                    throw new CertificateException("TSL signature validation failed");
                }
                Files.write(tsl, tslFromUrl);
                log.info("TSL cached at {} ({} bytes)", tsl, tslFromUrl.length);
            } else {
                log.info("Using cached TSL at {}", tsl);
            }

            TrustStatusListType tslUnsigned = TslReader.getTslUnsigned(tsl);
            this.tspServiceList = new TslInformationProvider(tslUnsigned).getTspServices();
            log.info("Loaded {} TSP services from TSL (seq {})", tspServiceList.size(),
                    tslUnsigned.getSchemeInformation().getTSLSequenceNumber());
        } catch (Exception e) {
            throw new IllegalStateException("Could not download or parse the gematik TSL", e);
        }
    }

    private boolean validateTsl(byte[] tslBytes) throws Exception {
        String certPath = production ? SIGNER_CERT_PU : SIGNER_CERT_RU;
        try (InputStream in = TslDownloader.class.getResourceAsStream(certPath)) {
            if (in == null) {
                throw new IllegalStateException("Missing bundled TSL signer certificate: " + certPath);
            }
            X509Certificate signer = CertReader.readX509(in.readAllBytes());
            return TslValidator.checkSignature(tslBytes, signer);
        }
    }

    /** The TSP services parsed from the TSL; {@code null} until {@link #refresh()} has run. */
    public List<TspService> getTspServiceList() {
        return tspServiceList;
    }

    public boolean isProduction() {
        return production;
    }
}
