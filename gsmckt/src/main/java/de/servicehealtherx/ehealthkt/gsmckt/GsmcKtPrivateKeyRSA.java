package de.servicehealtherx.ehealthkt.gsmckt;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

/**
 * A handle to the gSMC-KT's RSA authentication private key (PrK.SMKT.AUT.R2048). As with
 * {@link GsmcKtPrivateKeyEC}, the key never leaves the card; this object only references the
 * {@link GsmcKtCardIdentity} so the RSA signature SPIs ({@link GsmcKtPkcs1SignatureSpi},
 * {@link GsmcKtPssSignatureSpi}) can route signing to the card.
 */
public class GsmcKtPrivateKeyRSA implements RSAPrivateKey, SecretKey {

    private final transient GsmcKtCardIdentity card;
    private final String alias;

    public GsmcKtPrivateKeyRSA(GsmcKtCardIdentity card, String alias) {
        this.card = card;
        this.alias = alias;
    }

    public GsmcKtCardIdentity getCard() {
        return card;
    }

    public String getAlias() {
        return alias;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    @Override
    public BigInteger getModulus() {
        throw new UnsupportedOperationException("gSMC-KT RSA modulus is not exposed by the card handle");
    }

    @Override
    public BigInteger getPrivateExponent() {
        throw new UnsupportedOperationException("gSMC-KT RSA private exponent never leaves the card");
    }
}
