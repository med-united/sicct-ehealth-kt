# Implementation Plan — eHealth-KT (SICCT eHealth Kartenterminal)

## Context

We are building a **standalone eHealth-Kartenterminal (eHealth-KT)** in Java/Maven, per
gematik **gemSpec_KT** and the **SICCT 1.2.3** protocol. The terminal acts as a SICCT
**server** on TCP/TLS port **4742**; a Konnektor connects as client, pairs with the
terminal (EHEALTH TERMINAL AUTHENTICATE), and then drives local card slots (eGK / HBA /
SMC-B), the display, and secure PIN entry.

An existing project, `/home/manuel/git/virtual-nfc-card-terminal` (CardLink, ~40k LOC,
Java 21, Weld-CDI + Netty), already implements ~70% of the protocol work we need — but as
a **cloud bridge** that forwards APDUs over JMS/WebSocket to remote NFC phones. It has **no
local card slots, no display, no PIN pad**. We will **copy & refactor the reusable core**
(SICCT protocol, pairing, gSMC-KT crypto — ~7,700 LOC) into a clean standalone project and
**add the missing standalone-terminal pieces** (local PC/SC + simulated card slots,
display & secure PIN pad, full STATUS/capabilities, service discovery, config/management).

**Decisions confirmed with user:**
- Card backend: **pluggable** — PC/SC (`javax.smartcardio`) for hardware **+** a simulated
  backend (jcardsim / keystores) for hardware-free testing.
- Display & PIN: **pluggable** `TerminalUi` — headless auto-responder (tests) **+** a JavaFX
  GUI simulating the 2×16 display and a text input field for the PIN. The UI should depend on
  the capabilities of the PC/SC reader. If the reader has a PIN pad it must be used.
  There is a project that contains the APDUs that have to be send to verify the PIN of an eHBA:
  /home/manuel/git/ehba-cades-qes-sign
- Scope: **functional reference implementation** — full SICCT command set, pairing,
  gSMC-KT, secure PIN, status/capabilities, service discovery, remote PIN capabilitites.
  Firmware-update & management interface are **stubbed behind interfaces**.
  ESD/hardware/CC-certification are out of scope.

---

## 1. Specifications required & read

Already read (PDFs in `virtual-nfc-card-terminal/doc/`) and the online gemSpec_KT:

| Spec | Use |
|------|-----|
| **gemSpec_KT V3.15.0** (eHealth-KT) | Primary spec — terminal requirements, card types, pairing, PIN, display, firmware, mgmt. |
| **SICCT-Spezifikation V1.2.3** (+ Errata 2021-05-05) | Wire protocol: message envelope, command set, status words, slots, events, service discovery. |
| **gemSpec_gSMC-KT_ObjSys G2.1 V4.3.0** | gSMC-KT object system: DF.KT, EF.C.SMKT.AUT(2), keys, signing APDUs. |
| **ISO/IEC 7816-2/-3/-4** | Card contacts, T=1, APDU structure, status words. |

Referenced as needed during implementation (in repo `doc/`):
**gemSpec_COS V3.14.0** (card commands), **gemSpec_Krypt V2.27.0** (RSA-PSS, ECDSA
brainpoolP256r1, SHA-256, TLS cipher policy), **gemSpec_eGK_ObjSys G2.1 V4.6.0**,
**gemSpec_Kon V5.17.0** (Konnektor side of the SICCT dialog), and **gemLibPki** for X.509
chain validation.

---

## 2. Maven module structure

Multi-module Maven build, Java 21, plain Java (no CDI — lighter than the source project).

```
sicct-ehealth-kt/                     (parent POM, dependencyManagement, build plugins)
├── sicct-protocol/        SICCT wire protocol, pure & dependency-light
├── gsmckt/                gSMC-KT terminal identity + JCA signing provider
├── card/                  Card-slot abstraction: PC/SC + simulated backends
├── ui/                    Display + secure PIN pad: headless + Swing
├── terminal/              SICCT server, command interpreter, pairing, wiring
└── app/                   Bootstrap, config, CLI, service discovery, mgmt/fw stubs
```

Dependency direction: `app → terminal → {sicct-protocol, gsmckt, card, ui}`;
`gsmckt → card` (gSMC-KT is itself a card); `card → sicct-protocol` (shared APDU types).

**Why modules:** keeps the pure SICCT codec testable in isolation, lets the gSMC-KT JCA
provider be reused, and isolates the Swing/PC/SC (environment-dependent) code from headless CI.

---

## 3. Dependencies

| Dependency | Version (mgmt) | Where | Purpose |
|------------|----------------|-------|---------|
| Netty `netty-handler`, `netty-codec` | 4.1.124.Final | protocol, terminal | Async TLS/TCP server + codec pipeline. |
| BouncyCastle `bcprov/bctls/bcpkix-jdk18on` | 1.78.1 | gsmckt, terminal | RSA-PSS / ECDSA (brainpoolP256r1), BCJSSE TLS, X.509. |
| `javax.smartcardio` | JDK 21 built-in | card, gsmckt | PC/SC reader access. |
| jcardsim | 3.0.5+ | card (test/sim) | Simulated cards for hardware-free testing. |
| Jackson `databind` | 2.17.x | terminal, app | Pairing-block & config JSON (de)serialization. |
| SLF4J + Logback | 2.0.x / 1.5.x | all | Logging (replaces OpenSearch/SIEM in source). |
| picocli | 4.7.x | app | CLI (`--mode`, `--port`, `--config`). |
| gemLibPki | 2.1.7 | terminal | X.509 chain/role validation of Konnektor client certs. |
| JUnit 5, Mockito, AssertJ, awaitility | current | all (test) | Unit + protocol integration tests. |

Removed vs. source project: Artemis JMS, OpenSearch, AWS SNS, MQTT/Paho, WebSocket/Tyrus,
JPA/EclipseLink/H2/HikariCP, Weld-CDI, TPM/TSS.Java (TPM-backed storage kept as optional
interface, not a hard dependency).

---

## 4. Main classes & responsibilities

### sicct-protocol  *(port + clean-up of source `netty/sicct/codec` + protocol enums)*
- `SicctMessage` — parse/build the 10-byte SICCT envelope (type `6B/83/50`, slot/addr, seq, length) + payload. *(from `Message.java`)*
- `SicctDecoder` / `SicctEncoder` — Netty codecs bytes ↔ `SicctMessage`. *(from `SICCTDecoder.java`)*
- `MessageType`, `IccStatus`, `EventTag`, `ApduStatusWord` — protocol enums (COMMAND/RESPONSE/EVENT; CC_ABSENT…CC_SPECIFIC; keep-alive/sign-off; SW1SW2). *(from `MessageType/ICCStatus/EventTag/APDUResponseTrailer`)*
- `Apdu`, `ApduResponse`, `Tlv` — ISO 7816-4 command/response + BER-TLV data objects.

### gsmckt  *(port of source `smartcard/` package)*
- `GsmcKtCard` — connects to gSMC-KT, selects DF.KT, reads `EF.C.SMKT.AUT`/`AUT2`, runs PSO signing APDUs. *(from `GSMCktCard.java`)*
- `GsmcKtProvider` + `GsmcKtPrivateKeyRSA/EC` + `*SignatureSpi` — JCA provider so `Signature.getInstance(...)` routes signing onto the card (RSASSA-PSS SHA-256, NoneWithECDSA brainpoolP256r1). *(from `GSMCktCardProvider` et al.)*
- `TerminalIdentity` — wraps SM-KT cert + card-backed private key; exposes public key & cert fingerprint for pairing.
- `GematikCardUtil` — AIDs (eGK `D2760001448000`, gSMC-KT `…448003`), reader discovery, EF.DIR parsing. *(ported)*

### card  *(new — replaces the JMS bridge)*
- `CardSlotManager` — owns slots, tracks `IccStatus`, routes APDUs/RESET/REQUEST/EJECT. (Interface the interpreter depends on — replaces source `DeviceMessageProcessor`.)
- `CardSlotBackend` (interface) with `PcscCardSlotBackend` (`javax.smartcardio` `CardTerminals`/`CardChannel`) and `SimulatedCardSlotBackend` (jcardsim / test eGK images).
- `CardSlot` — one slot: present/powered state, ATR, T=1 transmit.

### ui  *(new)*
- `TerminalUi` (interface) — `display(String l1, String l2)`, `requestPin(PinParams)`, `requestPinModify(...)`, confirmation prompts.
- `HeadlessUi` — scripted/auto responses for tests/server mode.
- `SwingTerminalUi` — 2×16 display + numeric keypad window; masks PIN, never echoes digits.

### terminal  *(refactor of source `SICCTCommandInterpreter` + pairing/storage)*
- `SicctTlsServer` — Netty bootstrap, BCJSSE mutual-TLS (client-auth), gSMC-KT-backed server key, pipeline assembly, port 4742. *(from `SICCTTLSServer` + `SICCTTLSChannelInitializer`)*
- `SicctCommandInterpreter` — core state machine (`NoSicctTLS / InvalidClient / ClientWithoutPairing / ClientWithPairing`) + handlers for: INIT/CLOSE CT SESSION, RESET CT, REQUEST/EJECT ICC, GET STATUS (terminal/ICC/manufacturer/interface-capabilities/functional-unit), OUTPUT (→ `TerminalUi`), PERFORM VERIFICATION & **MODIFY VERIFICATION DATA** (→ secure PIN), and APDU-to-slot (→ `CardSlotManager`). *(ported, JMS/SIEM calls removed)*
- `EhealthTerminalAuthenticate` — CREATE/VALIDATE/ADD/ADD-EXPECTING pairing: gSMC-KT-signs the shared secret, `Hash(secret‖challenge)` validation. *(extracted from interpreter)*
- `SicctKeepAliveHandler` — reader/writer idle → sign-off / keep-alive events. *(ported)*
- `PairingBlock` + `PairingStore` (interface) + `FilePairingStore` (JSON) — shared-secret ↔ Konnektor-public-key persistence. *(ported; TPM impl left as optional interface)*
- `KonnektorCertValidator` — validates client cert chain/role via gemLibPki.

### app
- `EhealthKtApplication` (picocli `main`) — load config, build `TerminalIdentity`, choose card & UI backends, start server + discovery.
- `TerminalConfig` — typed config (port, slot map, backend selection, cert/keystore paths, timeouts). *(replaces source `ConfigProperties`, trimmed)*
- `ServiceDiscoveryServer` — SICCT service announcement / discovery responder (UDP). *(distilled from source `ServiceDiscoveryUdpServer`)*
- `FirmwareUpdateService`, `ManagementInterface` — **stub interfaces** with no-op/logging impls and clear TODOs (push/pull, admin roles) for the out-of-scope-now requirements.

---

## 5. Implementation phases

1. **Scaffold** parent + 6 module POMs, dependencyManagement, logging, CI-friendly headless profile.
2. **sicct-protocol**: port codec + enums + `Tlv`; unit-test against captured frames in source `src/test/resources` (pcap/websocket-messages).
3. **gsmckt**: port card + JCA provider; test signing with `SimulatedCardSlotBackend` and (optionally) a real gSMC-KT.
4. **card**: `CardSlotManager` + PC/SC + simulated backends; ATR/RESET/REQUEST/EJECT + APDU transmit.
5. **ui**: `TerminalUi` + headless; Swing later.
6. **terminal**: `SicctTlsServer`, refactored `SicctCommandInterpreter`, `EhealthTerminalAuthenticate`, pairing store, keep-alive — wire to card + ui via interfaces.
7. **app**: config, CLI, service discovery, stubs; end-to-end wiring.
8. **Swing UI** + polish + docs.

---

## 6. Verification

- **Unit tests** per module: envelope encode/decode round-trips against recorded SICCT frames;
  TLV parsing; gSMC-KT signature verifies against the SM-KT public key; pairing
  `Hash(secret‖challenge)` matches expected; state-machine command gating.
- **Integration test** (`terminal`): in-process Netty client performs full
  handshake → INIT CT SESSION → EHEALTH TERMINAL AUTHENTICATE (CREATE+VALIDATE) →
  REQUEST ICC → SELECT/READ on a simulated eGK → PERFORM VERIFICATION → CLOSE — all with
  `SimulatedCardSlotBackend` + `HeadlessUi`, no hardware. Driven from the recorded
  Konnektor traces in the source repo as fixtures.
- **Manual run**: `java -jar app/...jar --mode=sim` starts the server + Swing
  display/keypad; point a Konnektor (or the source project's test client) at `:4742`.
- **Hardware (optional)**: `--mode=pcsc` with a real gSMC-KT + eGK in PC/SC readers.
- `mvn verify` green in a headless environment (Swing/PC/SC modules guarded by profiles).

---

## 7. Open assumptions (flag if wrong)
- Copy-&-refactor the reusable core into this fresh repo (not a Maven dependency on the
  40k-LOC cloud app). License/authorship of ported code is OK to reuse (same author).
- gemLibPki and the gematik open-source card libs are resolvable from the same Maven repos
  the source project uses; if not, we vendor minimal equivalents.
- "Functional reference implementation" — not pursuing CC certification or real firmware signing now.
