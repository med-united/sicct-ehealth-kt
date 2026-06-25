package de.servicehealtherx.ehealthkt.gsmckt;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A {@link KeyStoreSpi} view over a {@link GsmcKtCardIdentity}: it exposes the card's SM-KT
 * authentication certificate(s) as TLS key entries whose private keys are card handles
 * ({@link GsmcKtPrivateKeyEC} / {@link GsmcKtPrivateKeyRSA}). A {@code KeyManagerFactory} can be
 * initialised from this keystore to make the gSMC-KT present its certificate as the TLS server
 * certificate while the signing stays on the card.
 *
 * <p>The keystore is read-only and is constructed directly around an already-connected card (see
 * {@link GsmcKtKeyStore#of(GsmcKtCardIdentity)}); it does not open its own PC/SC connection.
 * Ported from the CardLink {@code GSMCktCard} keystore.
 */
public class GsmcKtKeyStoreSpi extends KeyStoreSpi {

    /** Alias of the ECC entry (EF.C.SMKT.AUT2). */
    public static final String ALIAS_EC = "EF.C.SMKT.AUT2.XXXX";
    /** Alias of the RSA entry (EF.C.SMKT.AUT). */
    public static final String ALIAS_RSA = "EF.C.SMKT.AUT.XXXX";

    private final GsmcKtCardIdentity card;
    private final Map<String, Certificate> certificates = new LinkedHashMap<>();

    public GsmcKtKeyStoreSpi(GsmcKtCardIdentity card) {
        this.card = card;
        if (card.getEcCertificate() != null) {
            certificates.put(ALIAS_EC, card.getEcCertificate());
        }
        if (card.getRsaCertificate() != null) {
            certificates.put(ALIAS_RSA, card.getRsaCertificate());
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
        if (ALIAS_RSA.equals(alias)) {
            return new GsmcKtPrivateKeyRSA(card, alias);
        }
        if (ALIAS_EC.equals(alias)) {
            return new GsmcKtPrivateKeyEC(card, alias);
        }
        return null;
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Certificate cert = certificates.get(alias);
        return cert == null ? null : new Certificate[] {cert};
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return certificates.get(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(certificates.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return certificates.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return certificates.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return certificates.containsKey(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return false;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return certificates.entrySet().stream()
                .filter(e -> e.getValue().equals(cert))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return null;
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
        // No-op: the card is already connected and its certificates were read in the constructor.
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException("gSMC-KT keystore is read-only");
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("gSMC-KT keystore is read-only");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new KeyStoreException("gSMC-KT keystore is read-only");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("gSMC-KT keystore is read-only");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new KeyStoreException("gSMC-KT keystore is read-only");
    }
}
