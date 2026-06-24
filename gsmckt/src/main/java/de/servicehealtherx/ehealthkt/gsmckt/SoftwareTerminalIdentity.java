package de.servicehealtherx.ehealthkt.gsmckt;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * An in-memory gSMC-KT identity for hardware-free testing and the {@code sim} run mode.
 * Generates an RSA-2048 or EC brainpoolP256r1 key pair with a self-signed SM-KT certificate
 * and produces pairing signatures in the same byte format a real gSMC-KT would.
 *
 * <p>Note: a real Konnektor will reject this identity (no trusted gematik certificate chain);
 * it exists to exercise the pairing flow end-to-end in tests and demos.
 */
public class SoftwareTerminalIdentity implements TerminalIdentity {

    static {
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyType keyType;
    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    public SoftwareTerminalIdentity(KeyType keyType) {
        this.keyType = keyType;
        try {
            KeyPair pair = generateKeyPair(keyType);
            this.privateKey = pair.getPrivate();
            this.certificate = selfSign(pair, keyType);
        } catch (Exception e) {
            throw new IllegalStateException("Could not create software terminal identity", e);
        }
    }

    private static KeyPair generateKeyPair(KeyType type) throws Exception {
        if (type == KeyType.RSA) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        g.initialize(new ECNamedCurveGenParameterSpec(EcdsaSignatures.CURVE));
        return g.generateKeyPair();
    }

    private static X509Certificate selfSign(KeyPair pair, KeyType type) throws Exception {
        X500Name dn = new X500Name("CN=eHealth-KT SM-KT (software), O=servicehealtherx, C=DE");
        Instant now = Instant.now();
        String sigAlg = type == KeyType.RSA ? "SHA256withRSA" : "SHA256withECDSA";
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(pair.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)),
                dn,
                pair.getPublic());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    /**
     * The software private key, exposed so the TLS server can present the SM-KT certificate as its
     * server certificate in {@code sim} mode. (A real gSMC-KT keeps its private key on the card.)
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    @Override
    public KeyType getKeyType() {
        return keyType;
    }

    @Override
    public byte[] signPairingSecret(byte[] sharedSecret) {
        try {
            if (keyType == KeyType.RSA) {
                Signature sig = Signature.getInstance("RSASSA-PSS", BouncyCastleProvider.PROVIDER_NAME);
                sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                sig.initSign(privateKey, new SecureRandom());
                sig.update(sharedSecret);
                return sig.sign();
            }
            // EC: sign SHA-256(secret) with raw ECDSA, return plain r||s
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(sharedSecret);
            Signature sig = Signature.getInstance("NoneWithECDSA", BouncyCastleProvider.PROVIDER_NAME);
            sig.initSign(privateKey, new SecureRandom());
            sig.update(hash);
            return EcdsaSignatures.derToPlain(sig.sign());
        } catch (Exception e) {
            throw new IllegalStateException("Could not sign pairing secret", e);
        }
    }
}
