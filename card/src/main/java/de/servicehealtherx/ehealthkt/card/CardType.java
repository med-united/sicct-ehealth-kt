package de.servicehealtherx.ehealthkt.card;

import de.servicehealtherx.ehealthkt.sicct.Hex;

/**
 * Health-card types recognised by the eHealth-KT, identified by their application identifier (AID).
 */
public enum CardType {
    EGK("D2760001448000"),
    HBA("D27600014601"),
    SMC_B("D276000146"),
    GSMC_KT("D2760001448003"),
    UNKNOWN(null);

    private final byte[] aid;

    CardType(String aidHex) {
        this.aid = aidHex == null ? null : Hex.toBytes(aidHex);
    }

    public byte[] aid() {
        return aid;
    }
}
