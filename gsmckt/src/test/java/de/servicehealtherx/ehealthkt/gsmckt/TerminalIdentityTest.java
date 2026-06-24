package de.servicehealtherx.ehealthkt.gsmckt;

import org.junit.jupiter.api.Test;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;

class TerminalIdentityTest {

    private static final byte[] SHARED_SECRET = de.servicehealtherx.ehealthkt.sicct.Hex
            .toBytes("00112233445566778899AABBCCDDEEFF");

    @Test
    void ecPairingSignatureVerifies() {
        SoftwareTerminalIdentity id = new SoftwareTerminalIdentity(KeyType.EC);
        assertThat(id.getKeyType()).isEqualTo(KeyType.EC);
        assertThat(id.getPublicKey()).isInstanceOf(ECPublicKey.class);

        byte[] signature = id.signPairingSecret(SHARED_SECRET);
        assertThat(signature).hasSize(64); // plain r||s for brainpoolP256r1

        assertThat(PairingSignatures.verify(id.getPublicKey(), SHARED_SECRET, signature)).isTrue();
        // wrong secret must fail
        assertThat(PairingSignatures.verify(id.getPublicKey(),
                de.servicehealtherx.ehealthkt.sicct.Hex.toBytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), signature)).isFalse();
    }

    @Test
    void rsaPairingSignatureVerifies() {
        SoftwareTerminalIdentity id = new SoftwareTerminalIdentity(KeyType.RSA);
        assertThat(id.getKeyType()).isEqualTo(KeyType.RSA);
        assertThat(id.getPublicKey()).isInstanceOf(RSAPublicKey.class);

        byte[] signature = id.signPairingSecret(SHARED_SECRET);
        assertThat(signature).hasSize(256); // RSA-2048

        assertThat(PairingSignatures.verify(id.getPublicKey(), SHARED_SECRET, signature)).isTrue();
    }

    @Test
    void ecdsaPlainDerRoundTrip() {
        SoftwareTerminalIdentity id = new SoftwareTerminalIdentity(KeyType.EC);
        byte[] plain = id.signPairingSecret(SHARED_SECRET);
        byte[] der = EcdsaSignatures.plainToDer(plain);
        byte[] back = EcdsaSignatures.derToPlain(der);
        assertThat(back).isEqualTo(plain);
    }

    @Test
    void selfSignedCertificateIsPresent() {
        SoftwareTerminalIdentity id = new SoftwareTerminalIdentity(KeyType.EC);
        assertThat(id.getCertificate()).isNotNull();
        assertThat(id.getCertificate().getSubjectX500Principal().getName()).contains("eHealth-KT");
    }
}
