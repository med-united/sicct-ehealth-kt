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

The terminal runs against physical PC/SC readers. On start-up it scans every connected reader for a
gSMC-KT and uses the first one it finds as its TLS server identity; the remaining readers are bound
as card slots and the reader list is re-scanned periodically, so a reader plugged in after start-up
is picked up automatically. An empty reader is fine — its slot simply reports "card absent".

```bash
java -jar app/target/ehealth-kt.jar --port 4742
```

With the JavaFX display + PIN keypad — build with the `javafx` profile (so `JavaFxTerminalUi` is
compiled into the `ui` jar), then start with JavaFX on the module path and `--ui JAVAFX`.

**Recommended — reuse the JavaFX jars Maven already downloaded** (no separate SDK download). The
`-Pjavafx` build fetches the platform-specific `org.openjfx` jars into your local Maven repository
(`~/.m2`); point `--module-path` straight at them:

```bash
mvn -Pjavafx install                                  # build incl. the JavaFX UI, fetches JavaFX into ~/.m2

M2=~/.m2/repository/org/openjfx
JFX_VER=23.0.1
JFX_CLASSIFIER=linux                                  # use: linux | linux-aarch64 | mac | mac-aarch64 | win
java --module-path "$M2/javafx-base/$JFX_VER/javafx-base-$JFX_VER-$JFX_CLASSIFIER.jar:$M2/javafx-graphics/$JFX_VER/javafx-graphics-$JFX_VER-$JFX_CLASSIFIER.jar:$M2/javafx-controls/$JFX_VER/javafx-controls-$JFX_VER-$JFX_CLASSIFIER.jar" \
     --add-modules javafx.controls \
     -jar app/target/ehealth-kt.jar --port 4742 --ui JAVAFX
```

**Alternative — download the JavaFX SDK explicitly:**

```bash
mvn -Pjavafx install                                  # build incl. the JavaFX UI

wget -O /tmp/javafx-sdk.zip \
     https://download2.gluonhq.com/openjfx/23.0.1/openjfx-23.0.1_linux-x64_bin-sdk.zip
unzip -q /tmp/javafx-sdk.zip -d "$HOME/javafx"        # -> $HOME/javafx/javafx-sdk-23.0.1/lib

java --module-path "$HOME/javafx/javafx-sdk-23.0.1/lib" --add-modules javafx.controls \
     -jar app/target/ehealth-kt.jar --port 4742 --ui JAVAFX
```

If JavaFX is missing at runtime the app logs a warning and falls back to the headless UI.

Key options: `--port`, `--ui HEADLESS|JAVAFX`, `--pairing-file`, `--pin`, `--terminal-name`,
`--tsl-production`, `--no-konnektor-trust`, `--no-discovery`. See `--help`.

## Secure PIN entry

If the PC/SC reader exposes a secure PIN pad (`FEATURE_VERIFY_PIN_DIRECT`), PIN verification runs
on the reader. Otherwise the PIN is entered on the terminal UI ("remote PIN") and sent to the card
as an ISO format-2 PIN block. The verify APDUs follow the eHBA reference implementation.

## Status / scope

Functional reference implementation: full SICCT command set, pairing, gSMC-KT signing, secure/remote
PIN, status & service discovery, end-to-end tested over real mutual TLS without hardware
(`terminal` → `SicctEndToEndTest`). Firmware update and the management interface are stubbed behind
interfaces. Brainpool-curve TLS uses the BouncyCastle JSSE provider, with the gSMC-KT-backed TLS key
manager presenting the card-resident SM-KT certificate and signing the handshake on the card.
ESD/hardware/CC-certification are out of scope.
