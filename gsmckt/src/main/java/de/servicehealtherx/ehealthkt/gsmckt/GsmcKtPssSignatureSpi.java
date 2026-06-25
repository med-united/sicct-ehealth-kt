package de.servicehealtherx.ehealthkt.gsmckt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * An RSASSA-PSS ({@code SHA256withRSAandMGF1} / {@code RSASSA-PSS}) {@link SignatureSpi} backed by
 * the gSMC-KT's RSA authentication key. Unlike the PKCS#1 path, BCJSSE supplies the raw data and the
 * configured PSS parameters; this SPI hashes the data with the requested digest and the card
 * performs the EMSA-PSS encoding and RSA primitive ({@link GsmcKtCardIdentity#signPss(byte[])},
 * algId 0x05 {@code signPSS}).
 *
 * <p>As with {@link GsmcKtPkcs1SignatureSpi}, RSA peer verification is left to the TUC_PKI_018 trust
 * manager. Ported from the CardLink {@code GSMCktCardRSASSAPSSSignatureSpi}.
 */
public class GsmcKtPssSignatureSpi extends SignatureSpi {

    private MessageDigest md = new NullMessageDigest();
    private boolean digestReset = true;
    private GsmcKtCardIdentity card;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        // Verification is handled by the TUC_PKI_018 trust manager; see class javadoc.
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (!(privateKey instanceof GsmcKtPrivateKeyRSA rsaKey)) {
            throw new InvalidKeyException("Only GsmcKtPrivateKeyRSA is supported, got "
                    + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        this.card = rsaKey.getCard();
        resetDigest();
    }

    private void resetDigest() {
        if (!digestReset) {
            md.reset();
            digestReset = true;
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        md.update(b);
        digestReset = false;
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        md.update(b, off, len);
        digestReset = false;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (card == null) {
            throw new SignatureException("Signature not initialised for signing");
        }
        digestReset = true;
        return card.signPss(md.digest());
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return true;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (!(params instanceof PSSParameterSpec pss)) {
            return;
        }
        if (!digestReset) {
            throw new ProviderException("Cannot set parameters during operation");
        }
        String hashAlg = pss.getDigestAlgorithm();
        if (md == null || !md.getAlgorithm().equalsIgnoreCase(hashAlg)) {
            try {
                this.md = MessageDigest.getInstance(hashAlg);
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidAlgorithmParameterException("Unsupported digest algorithm " + hashAlg, e);
            }
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) {
        // No-op.
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) {
        return null;
    }
}
