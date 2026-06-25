package de.servicehealtherx.ehealthkt.gsmckt;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A {@code NoneWithRSA} / {@code SHA256withRSA} {@link SignatureSpi} that produces RSASSA-PKCS1-v1_5
 * signatures with the gSMC-KT's RSA authentication key. BCJSSE builds the PKCS#1 {@code DigestInfo}
 * and feeds it through this SPI's (null) digest; the bytes are then signed by the card
 * ({@link GsmcKtCardIdentity#signPkcs1(byte[])}, algId 0x02 {@code signPKCS1_V1_5}).
 *
 * <p>Used only for TLS RSA cipher suites; the ECC path ({@link GsmcKtNoneWithEcdsaSignatureSpi}) is
 * preferred per the gematik ECC migration. Verification of an RSA peer's {@code CertificateVerify}
 * is not re-implemented here — client-certificate trust is established by the TUC_PKI_018 trust
 * manager (full chain + status validation); this mirrors the CardLink reference
 * {@code GSMCktCardPKCS1SignatureSpi}.
 *
 * <p>Ported from the CardLink {@code GSMCktCardPKCS1SignatureSpi}.
 */
public class GsmcKtPkcs1SignatureSpi extends SignatureSpi {

    private final MessageDigest md = new NullMessageDigest();
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
        md.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        md.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        md.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (card == null) {
            throw new SignatureException("Signature not initialised for signing");
        }
        return card.signPkcs1(md.digest());
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return true;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) {
        // No parameters are used.
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
