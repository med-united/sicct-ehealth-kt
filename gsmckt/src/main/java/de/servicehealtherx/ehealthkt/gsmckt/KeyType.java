package de.servicehealtherx.ehealthkt.gsmckt;

/**
 * Key type of the gSMC-KT terminal identity (SM-KT).
 */
public enum KeyType {
    /** RSA-2048; pairing signature is RSASSA-PSS over the shared secret (256 bytes). */
    RSA,
    /** ECDSA on brainpoolP256r1; pairing signature is plain r||s over SHA-256(secret) (64 bytes). */
    EC
}
