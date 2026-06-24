package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Verifies a pairing signature against the SM-KT public key — i.e. the check a Konnektor
 * performs after EHEALTH TERMINAL AUTHENTICATE (CREATE). Mirrors
 * {@link SoftwareTerminalIdentity#signPairingSecret(byte[])}.
 */
public final class PairingSignatures {

    static {
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PairingSignatures() {
    }

    public static boolean verify(PublicKey publicKey, byte[] sharedSecret, byte[] signature) {
        try {
            if (publicKey instanceof ECPublicKey) {
                byte[] hash = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
                Signature sig = Signature.getInstance("NoneWithECDSA", BouncyCastleProvider.PROVIDER_NAME);
                sig.initVerify(publicKey);
                sig.update(hash);
                return sig.verify(EcdsaSignatures.plainToDer(signature));
            }
            Signature sig = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
            sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            sig.initVerify(publicKey);
            sig.update(sharedSecret);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
