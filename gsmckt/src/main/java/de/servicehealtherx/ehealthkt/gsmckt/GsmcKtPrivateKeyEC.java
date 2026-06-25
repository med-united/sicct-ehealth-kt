package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

import javax.crypto.SecretKey;
import java.math.BigInteger;

/**
 * A handle to the gSMC-KT's ECC authentication private key (PrK.SMKT.AUT.E256, brainpoolP256r1).
 * The key material never leaves the card; this object only carries a reference to the
 * {@link GsmcKtCardIdentity} so {@link GsmcKtNoneWithEcdsaSignatureSpi} can route signing to the
 * card's PSO Compute Digital Signature command. {@link #getEncoded()} therefore returns no usable
 * bytes, and {@link #getD()} is a placeholder.
 */
public class GsmcKtPrivateKeyEC implements ECPrivateKey, SecretKey {

    private final transient GsmcKtCardIdentity card;
    private final String alias;

    public GsmcKtPrivateKeyEC(GsmcKtCardIdentity card, String alias) {
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
        return "EC";
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
    public ECParameterSpec getParameters() {
        return ECNamedCurveTable.getParameterSpec(EcdsaSignatures.CURVE);
    }

    @Override
    public BigInteger getD() {
        return BigInteger.ONE;
    }
}
