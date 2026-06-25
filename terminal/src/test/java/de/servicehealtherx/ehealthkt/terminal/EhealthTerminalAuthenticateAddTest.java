package de.servicehealtherx.ehealthkt.terminal;

import de.servicehealtherx.ehealthkt.gsmckt.KeyType;
import de.servicehealtherx.ehealthkt.gsmckt.SoftwareTerminalIdentity;
import de.servicehealtherx.ehealthkt.sicct.Hex;
import de.servicehealtherx.ehealthkt.sicct.StatusWord;
import de.servicehealtherx.ehealthkt.sicct.Tlv;
import de.servicehealtherx.ehealthkt.terminal.pairing.InMemoryPairingStore;
import de.servicehealtherx.ehealthkt.terminal.pairing.PairingBlock;
import de.servicehealtherx.ehealthkt.ui.HeadlessUi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for EHEALTH TERMINAL AUTHENTICATE ADD Phase 1 (P2=03) and Phase 2 (P2=04),
 * gemSpec_KT SEQ_KT_0003 / SEQ_KT_0004.
 */
class EhealthTerminalAuthenticateAddTest {

    private static final byte[] SHARED_SECRET = Hex.toBytes("000102030405060708090A0B0C0D0E0F");
    private static final String KEY_ORIGINAL = "aa".repeat(32);
    private static final String KEY_NEW = "bb".repeat(32);

    private InMemoryPairingStore store;
    private EhealthTerminalAuthenticate auth;

    @BeforeEach
    void setUp() {
        store = new InMemoryPairingStore();
        auth = new EhealthTerminalAuthenticate(
                new SoftwareTerminalIdentity(KeyType.RSA), store, new HeadlessUi());
    }

    private PairingBlock blockWithSecret(String... keys) {
        PairingBlock block = new PairingBlock(Hex.toHex(SHARED_SECRET));
        for (String k : keys) {
            block.addPublicKey(k);
        }
        store.add(block);
        return block;
    }

    private static byte[] sha256(byte[]... parts) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(Hex.concat(parts));
    }

    private static byte[] responseDo(byte[] hash) {
        return new Tlv(0xD6, hash).toBytes();
    }

    // --- Phase 1 -------------------------------------------------------------

    @Test
    void phase1GeneratesChallengeOfRequestedLength() {
        byte[] challenge = auth.addPhase1(32);
        assertThat(challenge).hasSize(32);
    }

    @Test
    void phase1RejectsLengthBelowMinimum() {
        assertThat(auth.addPhase1(15)).isNull();
    }

    @Test
    void phase1RejectsLengthAboveMaximum() {
        assertThat(auth.addPhase1(128)).isNull();
    }

    // --- Phase 2 -------------------------------------------------------------

    @Test
    void phase2BindsNewKonnektorKeyToMatchingBlock() throws Exception {
        PairingBlock block = blockWithSecret(KEY_ORIGINAL);
        byte[] challenge = auth.addPhase1(16);

        byte[] result = auth.addPhase2(challenge, responseDo(sha256(challenge, SHARED_SECRET)), KEY_NEW);

        assertThat(result).isEqualTo(StatusWord.SUCCESS.toBytes());
        assertThat(block.getPublicKeysHex()).containsExactly(KEY_ORIGINAL, KEY_NEW);
    }

    @Test
    void phase2IsIdempotentWhenKeyAlreadyPresent() throws Exception {
        PairingBlock block = blockWithSecret(KEY_NEW);
        byte[] challenge = auth.addPhase1(16);

        byte[] result = auth.addPhase2(challenge, responseDo(sha256(challenge, SHARED_SECRET)), KEY_NEW);

        assertThat(result).isEqualTo(StatusWord.SUCCESS.toBytes());
        assertThat(block.getPublicKeysHex()).containsExactly(KEY_NEW);
    }

    @Test
    void phase2EvictsOldestKeyWhenBlockFull() throws Exception {
        PairingBlock block = blockWithSecret("11".repeat(32), "22".repeat(32), "33".repeat(32));
        byte[] challenge = auth.addPhase1(16);

        auth.addPhase2(challenge, responseDo(sha256(challenge, SHARED_SECRET)), KEY_NEW);

        // The oldest key ("11..") is overwritten; the rest survive and the new key is appended.
        assertThat(block.getPublicKeysHex()).containsExactly("22".repeat(32), "33".repeat(32), KEY_NEW);
    }

    @Test
    void phase2MovesKeyOutOfOtherBlock() throws Exception {
        PairingBlock other = new PairingBlock(Hex.toHex(Hex.toBytes("FF".repeat(16))));
        other.addPublicKey(KEY_NEW);
        store.add(other);
        PairingBlock target = blockWithSecret(KEY_ORIGINAL);
        byte[] challenge = auth.addPhase1(16);

        auth.addPhase2(challenge, responseDo(sha256(challenge, SHARED_SECRET)), KEY_NEW);

        assertThat(other.getPublicKeysHex()).doesNotContain(KEY_NEW);
        assertThat(target.getPublicKeysHex()).contains(KEY_NEW);
    }

    @Test
    void phase2RejectsMissingResponseDo() {
        blockWithSecret(KEY_ORIGINAL);
        byte[] challenge = auth.addPhase1(16);

        assertThat(auth.addPhase2(challenge, new byte[0], KEY_NEW))
                .isEqualTo(StatusWord.REFERENCED_DATA_NOT_FOUND.toBytes());
    }

    @Test
    void phase2RejectsWrongResponseLength() {
        blockWithSecret(KEY_ORIGINAL);
        byte[] challenge = auth.addPhase1(16);

        assertThat(auth.addPhase2(challenge, responseDo(new byte[31]), KEY_NEW))
                .isEqualTo(StatusWord.INCORRECT_DATA_FIELD.toBytes());
    }

    @Test
    void phase2RejectsWhenNoBlockMatches() throws Exception {
        blockWithSecret(KEY_ORIGINAL);
        byte[] challenge = auth.addPhase1(16);
        byte[] wrongHash = sha256(challenge, Hex.toBytes("FF".repeat(16)));

        assertThat(auth.addPhase2(challenge, responseDo(wrongHash), KEY_NEW))
                .isEqualTo(StatusWord.NO_INFORMATION.toBytes());
    }
}
