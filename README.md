# SICCT eHealth-KT

A standalone **eHealth-Kartenterminal (eHealth-KT)** in Java, implementing the gematik
**gemSpec_KT** terminal behaviour over the **SICCT 1.2.3** protocol. The terminal acts as a SICCT
server on TCP/TLS port **4742**; a Konnektor connects as client, pairs with the terminal
(EHEALTH TERMINAL AUTHENTICATE) and then drives local card slots (eGK / HBA / SMC-B), the display
and secure PIN entry.

The SICCT protocol core, the gSMC-KT pairing signatures and the keep-alive handling are derived
from the CardLink `virtual-nfc-card-terminal`; the local card slots (PC/SC + simulated), the
display & secure PIN pad, service discovery and the standalone wiring are new here.

See [`PLAN.md`](PLAN.md) for the design and the specifications used.

## Modules

| Module | Responsibility |
|--------|----------------|
| `sicct-protocol` | SICCT envelope codec, BER-TLV, status words, enums (no card/IO deps). |
| `gsmckt` | gSMC-KT terminal identity & pairing signatures: software (`SoftwareTerminalIdentity`) and real PC/SC (`GsmcKtCardIdentity`). |
| `card` | Card-slot abstraction: `PcscCardSlotBackend` (incl. reader PIN-pad detection) and `SimulatedCardSlotBackend`. |
| `ui` | `TerminalUi`: `HeadlessUi` (default) and a JavaFX simulator (`-Pjavafx`). |
| `terminal` | `SicctTlsServer`, `SicctCommandInterpreter` (state machine), `EhealthTerminalAuthenticate`, pairing store, keep-alive. |
| `app` | Bootstrap, CLI (picocli), TLS context, service discovery, firmware/management stubs. |

## Build

```bash
mvn install                 # build + tests (headless, no hardware needed)
mvn -Pjavafx -pl ui install # also build the JavaFX terminal simulator
```

Requires JDK 21+. Most-recent stable dependency versions are pinned in the parent POM
(Netty 4.2, BouncyCastle 1.84, JUnit 6, etc.).

## Run

Simulation mode (no hardware) — software gSMC-KT, simulated eGK in slot 2:

```bash
java -jar app/target/ehealth-kt.jar --mode SIM --port 4742
```

With the JavaFX display + PIN keypad (build `ui` with `-Pjavafx` and put JavaFX on the runtime
module path), add `--ui JAVAFX`.

Hardware mode — gSMC-KT and cards in PC/SC readers:

```bash
java -jar app/target/ehealth-kt.jar --mode PCSC --gsmckt-reader 0
```

Key options: `--mode SIM|PCSC`, `--port`, `--key-type RSA|EC`, `--ui HEADLESS|JAVAFX`,
`--pairing-file`, `--egk-slot`, `--pin`, `--no-discovery`. See `--help`.

## Secure PIN entry

If the PC/SC reader exposes a secure PIN pad (`FEATURE_VERIFY_PIN_DIRECT`), PIN verification runs
on the reader. Otherwise the PIN is entered on the terminal UI ("remote PIN") and sent to the card
as an ISO format-2 PIN block. The verify APDUs follow the eHBA reference implementation.

## Status / scope

Functional reference implementation: full SICCT command set, pairing, gSMC-KT signing, secure/remote
PIN, status & service discovery, end-to-end tested over real mutual TLS without hardware
(`terminal` → `SicctEndToEndTest`). Firmware update and the management interface are stubbed behind
interfaces. Brainpool-curve TLS uses the BouncyCastle JSSE provider. A gSMC-KT-backed TLS key
manager for `--mode PCSC` (card-resident TLS private key) is the main remaining piece for full
hardware operation. ESD/hardware/CC-certification are out of scope.
