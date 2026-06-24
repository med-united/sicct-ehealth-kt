package de.servicehealtherx.ehealthkt.gsmckt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

/**
 * A gSMC-KT terminal identity backed by a real card in a PC/SC reader. Ported from the
 * CardLink {@code GSMCktCard}: selects DF.KT, reads the SM-KT AUT certificate, and produces
 * pairing signatures via PSO Compute Digital Signature.
 *
 * <p>APDUs follow gemSpec_COS V3.14.0 and gemSpec_gSMC-KT_ObjSys G2.1 V4.3.0.
 */
public class GsmcKtCardIdentity implements TerminalIdentity {

    private static final Logger log = LoggerFactory.getLogger(GsmcKtCardIdentity.class);

    // SELECT DF.KT (AID D2 76 00 01 44 00)
    private static final byte[] SELECT_DF_KT =
            {0x00, (byte) 0xa4, 0x04, 0x0c, 0x06, (byte) 0xd2, 0x76, 0x00, 0x01, 0x44, 0x00};

    private final CardChannel channel;
    private final KeyType keyType;
    private final X509Certificate certificate;

    public GsmcKtCardIdentity(CardChannel channel) {
        this.channel = channel;
        // Prefer the ECC identity (EF.C.SMKT.AUT2, SFI 0x04); fall back to RSA (EF.C.SMKT.AUT, SFI 0x01).
        X509Certificate ecCert = tryReadCertificate((byte) 0x04);
        if (ecCert != null && ecCert.getPublicKey() instanceof ECPublicKey) {
            this.certificate = ecCert;
            this.keyType = KeyType.EC;
        } else {
            X509Certificate rsaCert = tryReadCertificate((byte) 0x01);
            if (rsaCert == null) {
                throw new IllegalStateException("Could not read any SM-KT certificate from gSMC-KT");
            }
            this.certificate = rsaCert;
            this.keyType = KeyType.RSA;
        }
        log.info("gSMC-KT identity loaded: keyType={}, subject={}", keyType, certificate.getSubjectX500Principal());
    }

    private X509Certificate tryReadCertificate(byte sfi) {
        try {
            byte[] der = readFileFromDfKt(sfi);
            if (der == null || der.length == 0) {
                return null;
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            log.debug("Could not read certificate from SFI {}", sfi, e);
            return null;
        }
    }

    private byte[] readFileFromDfKt(byte sfi) {
        transmit("SELECT DF.KT", SELECT_DF_KT, false);
        byte[] readBinary = {0x00, (byte) 0xb0, (byte) (0x80 + sfi), 0x00, 0x00, 0x00, 0x00};
        return transmit("READ BINARY", readBinary, true);
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
        if (keyType == KeyType.EC) {
            byte[] hash = sha256(sharedSecret);
            // ECDSA: algId 0x00, keyRef 0x06 -> card returns plain r||s (64 bytes)
            return pso(hash, (byte) 0x00, (byte) 0x06);
        }
        // RSASSA-PSS: algId 0x05, keyRef 0x02 -> 256 bytes
        return pso(sharedSecret, (byte) 0x05, (byte) 0x02);
    }

    private byte[] pso(byte[] message, byte algId, byte keyRef) {
        transmit("SELECT DF.KT", SELECT_DF_KT, false);
        // MSE: select private key + algorithm
        byte[] mse = {0x00, 0x22, 0x41, (byte) 0xB6, 0x06,
                (byte) 0x84, 0x01, (byte) (0x80 | keyRef), (byte) 0x80, 0x01, algId};
        transmit("MSE", mse, false);

        // PSO Compute Digital Signature, extended length
        ByteArrayOutputStream apdu = new ByteArrayOutputStream();
        apdu.writeBytes(new byte[]{0x00, 0x2a, (byte) 0x9e, (byte) 0x9a});
        apdu.write(0x00); // extended length marker
        apdu.write((message.length >> 8) & 0xFF);
        apdu.write(message.length & 0xFF);
        apdu.writeBytes(message);
        apdu.write(0x00); // Le
        apdu.write(0x00);
        return transmit("PSO Compute Digital Signature", apdu.toByteArray(), false);
    }

    private byte[] transmit(String action, byte[] command, boolean allowNon9000) {
        try {
            ResponseAPDU response = channel.transmit(new CommandAPDU(command));
            if (response.getSW() != 0x9000 && !allowNon9000) {
                throw new IllegalStateException(action + " failed, SW=" + Integer.toHexString(response.getSW()));
            }
            return response.getData();
        } catch (CardException e) {
            throw new IllegalStateException(action + " transmit failed", e);
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(in);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        // The card lifecycle (connect/disconnect) is owned by the caller that opened the channel.
    }
}
