package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * A {@code NoneWithECDSA} {@link SignatureSpi} that signs with the gSMC-KT's ECC authentication key.
 * BCJSSE pre-computes the TLS handshake hash and calls this SPI in raw ("None") mode; signing is
 * delegated to the card ({@link GsmcKtCardIdentity#signEcdsa(byte[])}), which returns the plain
 * {@code r||s}. The result is re-encoded as the DER {@code SEQUENCE} the TLS wire format expects.
 *
 * <p>Verification (reached when BCJSSE checks the peer's ECDSA {@code CertificateVerify}) is
 * delegated to the standard BouncyCastle {@code NoneWithECDSA} implementation, so installing this
 * SPI as an override does not weaken client-certificate proof-of-possession.
 *
 * <p>Ported from the CardLink {@code GSMCktCardNoneWithECDSASignatureSpi}.
 */
public class GsmcKtNoneWithEcdsaSignatureSpi extends SignatureSpi {

    /** Clean provider used only for delegated verification (never the overridden one). */
    private static final BouncyCastleProvider VERIFY_PROVIDER = new BouncyCastleProvider();

    private GsmcKtCardIdentity card;
    private byte[] buffer;
    private Signature verifyDelegate;

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        if (!(privateKey instanceof GsmcKtPrivateKeyEC ecKey)) {
            throw new InvalidKeyException("Only GsmcKtPrivateKeyEC is supported, got "
                    + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        this.card = ecKey.getCard();
        this.buffer = null;
        this.verifyDelegate = null;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        try {
            this.verifyDelegate = Signature.getInstance("NoneWithECDSA", VERIFY_PROVIDER);
            this.verifyDelegate.initVerify(publicKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Could not initialise ECDSA verifier", e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[] {b}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (verifyDelegate != null) {
            verifyDelegate.update(b, off, len);
            return;
        }
        // Signing: BCJSSE supplies the full pre-computed hash in a single update.
        byte[] copy = new byte[len];
        System.arraycopy(b, off, copy, 0, len);
        this.buffer = copy;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (card == null || buffer == null) {
            throw new SignatureException("Signature not initialised for signing");
        }
        byte[] plain = card.signEcdsa(buffer);
        return EcdsaSignatures.plainToDer(plain);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyDelegate == null) {
            throw new SignatureException("Signature not initialised for verification");
        }
        return verifyDelegate.verify(sigBytes);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) {
        // No parameters are used for NoneWithECDSA.
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
