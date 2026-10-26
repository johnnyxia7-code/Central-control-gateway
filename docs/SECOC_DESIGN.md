# HPC Gateway – SecOC (Secure Onboard Communication)

## 1. Purpose

E2E protection (CRC + counter) detects corrupted or lost frames. It cannot
detect a **deliberate** manipulation: anyone on the bus can compute a CRC.
SecOC (AUTOSAR SWS SecOC) adds a cryptographic MAC and a freshness value to
safety- and security-relevant PDUs. A receiver then knows that:

- the data comes from a sender that holds the key (**authenticity**),
- it was not changed on the way (**integrity**),
- it is not a recorded old message played back (**freshness / replay protection**).

The central gateway sits between security domains. A secured PDU it receives
is **verified** before anything is routed. A secured PDU it sends is
**authenticated** with the key of the target domain. A request from the ADAS
domain therefore reaches the chassis bus only after the gateway has checked it,
and in the format and under the key the chassis ECUs expect.

```
 ADAS ECU ──ETH_ADAS──► gateway ──CHS_CAN──► EPS
  K_ADAS_GW, 64-bit FV  verify  │  re-authenticate      K_GW_CHS, 8-bit FV
  64-bit MAC (16 B)             │                       24-bit MAC (4 B)
                                └─ failure: drop + IdsM security event,
                                   timeout → safe substitution values
```

## 2. Secured I-PDU format

```
 | Authentic I-PDU (signals, E2E) | truncated FV | truncated MAC | pad to byte |
                                   └──────── SecOC trailer ─────────┘
```

| Element | Content |
|---------|---------|
| Data to authenticator | `Data ID (16 bit) ‖ Authentic I-PDU ‖ complete FV (⌈FV bits / 8⌉ bytes, big endian)` |
| MAC | AES-128-CMAC (NIST SP 800-38B / RFC 4493) over the data to authenticator |
| Truncated MAC | `macTxBits` most significant bits |
| Truncated FV | `freshnessTxBits` least significant bits of the freshness counter |
| Packing | FV then MAC, MSB first, without gaps; the trailer is padded with zeros to a byte |

Configuration per PDU (`secoc::SecOcConfig`):

| Parameter | Meaning |
|-----------|---------|
| `dataId` | SecOC Data ID; it binds the MAC to this PDU, so a MAC cannot be reused for another PDU |
| `keyId` | key slot in the crypto service (HSM) |
| `freshnessBits` | length of the complete freshness counter (≤ 64) |
| `freshnessTxBits` | transmitted LSBs (0 = none, = `freshnessBits` = full) |
| `macTxBits` | transmitted MAC bits (8..128) |
| `acceptanceWindow` | maximum accepted counter jump on reception, 0 = unlimited |
| `verifyAttempts` | FV candidates tried; recovers after more than 2^`freshnessTxBits` lost PDUs |

The reference table uses two profiles:

| Bus | Profile | Trailer |
|-----|---------|---------|
| CAN / CAN FD | synchronised FV from the gateway's FV master (§4): 2-bit reset flag + 6-bit message counter sent, 24-bit MAC, 2 verify attempts | 4 bytes |
| Ethernet | full 64-bit counter, 64-bit MAC, acceptance window 1000 | 16 bytes |

## 3. Freshness value management

The freshness value manager (`secoc::FreshnessManager`) supports two modes per
PDU (`SecOcConfig::freshnessMode`):

| Mode | Complete FV | Transmitted | Used for |
|------|-------------|-------------|----------|
| `Counter` | one monotonic counter per Data ID | its LSBs (or all of it) | Ethernet PDUs |
| `TripReset` | trip counter ‖ reset counter ‖ message counter | reset flag ‖ message counter LSBs | CAN PDUs, with the gateway as FV master (§4) |

### 3.1 Counter mode

One Tx and one Rx counter per Data ID.

- **Transmission:** the counter is incremented for every secured PDU. When it
  would overflow `freshnessBits` the PDU is no longer sent (`secocTxFailures`);
  key and counter renewal is then required.
- **Reception:** the complete FV is rebuilt from the received LSBs and the
  latest accepted value:

  ```
  if received LSBs > LSBs(latest):  candidate = MSBs(latest) | received
  else:                             candidate = (MSBs(latest) + 1) | received
  ```

  The candidate must be newer than the latest accepted value, within the
  acceptance window, and must produce the received MAC. With
  `verifyAttempts > 1` the next epoch (+2^`freshnessTxBits`) is tried as well.
  Only a successful verification advances the Rx counter, so forged frames
  cannot push it forward.
- **Persistence:** with `--fv-store`, each proposed Tx/Rx counter is committed
  before the secured transmission or verified reception can be used. The store
  is written to `.tmp`, fsynced, renamed, and its parent directory fsynced.
  Restarts restore exact counters, with no jump beyond the peer's window.
  A write failure throws before publishing the counter and stops the Linux
  gateway; a corrupt store also prevents startup. The trip counter uses the
  same commit hook before its first use, including reset-counter overflow.
  Omitting `--fv-store` selects volatile bench operation and logs a warning.

This synchronous file backend trades throughput and flash wear for crash
durability. Production targets should supply an NvM/HSM commit hook with the
same durable-before-use contract, sized for the traffic rate. Any reservation
scheme must be designed together with the peer's acceptance window. A lost
or deleted store requires reprovisioning/synchronization; do not reset
counters under existing keys. When upgrading from the old periodic store,
quiesce traffic and establish current counters at both peers or reprovision:
an old snapshot cannot recover counters used since its last save.

| Attack | Result |
|--------|--------|
| Payload changed | `VERIFICATION_FAILURE` (MAC) |
| Forged with a wrong key | `VERIFICATION_FAILURE` |
| MAC copied to another PDU | `VERIFICATION_FAILURE` (Data ID is part of the MAC) |
| Replay, full FV transmitted | `FRESHNESS_FAILURE` |
| Replay, truncated FV | `VERIFICATION_FAILURE` (the FV is rebuilt into the next epoch, so the MAC no longer matches) |
| Counter far ahead of the window | `FRESHNESS_FAILURE` |

### 3.2 Synchronised mode (trip / reset / message counter)

```
complete FV = TripCounter (16) | ResetCounter (20) | MessageCounter (26)   = 62 bits
truncated   = ResetFlag (2 LSBs of ResetCounter) | MessageCounter LSBs (6) =  8 bits
```

- **Trip and reset counter:** shared by all PDUs and owned by the FV master.
  ECUs only adopt them from verified sync messages (§4).
- **Transmission:** the message counter is per Data ID. It restarts at 1 in
  every reset period and must not overflow inside a period. Without a valid
  sync, an ECU cannot send synchronised PDUs.
- **Reception:**
  - The reset counter is chosen among *current*, *−1* and *+1* by matching
    the reset flag. This tolerates a sender that sent just before a sync, or
    that received the sync before the receiver did.
  - The message counter is rebuilt from its LSBs relative to the last
    accepted value of the same reset period, or from 0 in a new period.
  - The complete FV must be newer than the last accepted one, and the MAC must
    match. With `verifyAttempts > 1` the next message counter epoch is tried as well.
- **No per-message Tx persistence:** a power cycle increments the trip counter,
  so every FV of the new trip is larger than any old one. Messages recorded
  before a restart are rebuilt with the new trip counter and fail the MAC.
  The shared file backend still commits accepted Rx counters with its snapshot.

## 4. Freshness value synchronisation master (`secoc::FreshnessSyncMaster`)

The central gateway is the FV master of the vehicle. It is the one ECU that
owns the trip and reset counters, and it distributes them to every bus.

```
 power-up        TripCounter = stored + 1 ── persisted to NvM before first use
                 ResetCounter = 0             └─ sync message on every bus
 every 1 s       ResetCounter + 1         ─── sync message on every bus
 reset overflow  TripCounter + 1, ResetCounter = 0 (persisted)
 trip overflow   master inactive: synchronised SecOC stops (key / counter renewal)
```

**Sync message** (`GW_FvSync_*`, CAN ID 0x0F0 on PT_CAN, CHS_CAN and BODY_CAN,
header ID 0xF000 on ETH_ADAS), 8 bytes:

```
| TripCounter (16) | ResetCounter (20) | MAC (28 MSBs) |
MAC = AES-128-CMAC(K_FV_MASTER, DataID 0x00F0 | TripCounter (4 B) | ResetCounter (4 B))
```

- **Ordering:** sent in the first gateway cycle after start-up, then once per
  reset cycle, before any secured PDU of that cycle is built. `requestSync()`
  resends the current counters, for example when an ECU wakes up.
- **Ethernet:** the sync PDU is marked `urgent`, so it is not held back by the
  datagram collection time.
- **Gateway's own PDUs:** the gateway uses the same counters for its
  `TripReset` PDUs (for example `GW_SteerTorqueReq`) and for verifying the
  ECUs' PDUs (for example `VCU_PowerLimit`).

**FV slave** (`secoc::FreshnessSyncSlave`, in the ECUs, the tests and the
simulator) accepts a sync message only if:
- its length is complete (otherwise `LENGTH_ERROR`);
- the MAC matches (otherwise `MAC_FAILURE`; a forged message cannot move the counters);
- trip ‖ reset is **newer** than the slave's current values (otherwise
  `STALE`; old sync messages cannot be replayed).

**Persistence of the trip counter.** The trip counter is the root of
freshness for every CAN PDU. If an old value were ever reused, recorded
messages of that trip would become valid again. Therefore:
- `FreshnessManager::takePersistRequest()` reports every new trip counter
  (start-up and reset counter overflow);
- the gateway process writes the snapshot to `--fv-store` (atomic rename)
  **before** the next cycle. It refuses to continue if that write fails;
- the snapshot file has a `trip <n>` line next to the Tx/Rx counters.

**Restore after an ECU exchange or NvM loss.** Slaves only follow increasing
counters. A gateway whose stored trip counter went backwards would therefore
be ignored until the counters are re-aligned. That is a workshop operation
(key and counter renewal), not something done automatically.

## 5. Gateway integration (`ccg_ethgw`)

`PduDefinition::secoc` marks a PDU as a secured I-PDU. Signals and E2E live in
the authentic part; the validator checks that they do not reach into the trailer.

**Reception** (`processPdu`)
1. Length check.
2. **SecOC verification.** On failure the PDU is dropped. Neither message nor
   signal routing sees it, and a `SecurityEvent` (PDU, channel, result, time) is
   recorded for the intrusion detection system (IdsM). The last 64 events are kept.
3. E2E check (on the authentic part) for signal routing.
4. Message routing and signal routing on the authentic part.

**Transmission** (`sendPdu`)
1. Assembled PDUs: signals written into the authentic buffer, then E2E protection.
2. **SecOC authentication** with the target PDU's key and the gateway's own
   freshness counter. A routed secured PDU is **re-authenticated**, not
   forwarded with the sender's MAC.
3. Transmission on CAN or into the Ethernet datagram container.

**Faults.** A failed verification is not a timeout by itself. The deadline
monitoring of the source PDU turns persistent attacks or a missing sender into
the configured substitution values. For the steering request that means
`GW_SteerReqActive = 0`, `GW_SteerTqReq = 0 Nm` (safe state), still sent
authenticated.

**Pass-through.** A PDU routed without `secoc` on source and target is copied
byte for byte, MAC included. This allows end-to-end SecOC between two ECUs
when the gateway is not a party to the key.

## 6. Crypto service

`secoc::ICryptoService` corresponds to the AUTOSAR Csm and works with key slots
(`hasKey`, `generateMac`, `verifyMac`). SecOC and the FV sync slave verify with
`verifyMac` (Csm_MacVerify), so a key manager can accept more than one key
generation during a key rollover.

| Implementation | Use | Key source |
|----------------|-----|------------|
| HSM driver (target) | series vehicles | keys provisioned at end of line or by OTA key management; they never leave the HSM |
| `keym::KeyManager` | gateway key management | SHE key slots updated over UDS, rollover with grace period, see [KEY_MANAGEMENT_DESIGN.md](KEY_MANAGEMENT_DESIGN.md); `--key-store FILE` |
| `SoftwareCryptoService` | bench, simulation, tests | `--keys FILE` (`KEY_ID=<32 hex digits>` per line) or `--demo-keys` (built-in **test keys**, bench only) |

The software AES-128 / CMAC (`ccg/crypto/aes_cmac.hpp`) has no dependencies and
is verified against:
- FIPS-197 and SP 800-38A AES known answers (encryption and decryption),
- RFC 4493 CMAC examples 1–4 (including the subkeys),
- OpenSSL 3 for 201 random keys and messages (test-only, built when OpenSSL is found).

MAC comparison runs in constant time over the truncated bits.

The gateway refuses to start (`RoutingConfigError`) if a secured PDU's key is
not available.

## 7. Reference configuration

| PDU | Bus | Role | Profile | Key | Data ID | Length (authentic + trailer) |
|-----|-----|------|---------|-----|---------|------------------------------|
| ADAS_SteerTorqueReq | ETH_ADAS 0x1003 | received | Ethernet | K_ADAS_GW | 0x1003 | 8 + 16 |
| GW_SteerTorqueReq | CHS_CAN 0x1B0 | assembled, on update | synchronised | K_GW_CHS | 0x01B0 | 4 + 4 |
| VCU_PowerLimit | PT_CAN 0x130 (FD) | received | synchronised | K_VCU_GW | 0x0130 | 12 + 4 |
| GW_FvSync_* | PT/CHS/BODY_CAN 0x0F0, ETH_ADAS 0xF000 | FV master sync message | – | K_FV_MASTER | 0x00F0 | 8 |
| VCU_PowerLimit_ADAS | ETH_ADAS 0x130 | message routing target | Ethernet | K_GW_ADAS | 0x2130 | 12 + 16 |

```
ccg_eth_gateway --bind ... --keys /etc/ccg/secoc.keys --fv-store /var/lib/ccg/freshness
ccg_eth_gw_sim     # genuine stream, tampered request, replay, timeout -> safe state
```

## 8. Limitations / next steps

- Timestamp-based freshness (time synchronisation) is not implemented, and
  neither are secondary FV masters or FV master redundancy.
- No secured I-PDU header (dynamic length) and no secured container PDUs. The
  authentic part has a fixed length.
- Key management (SHE key update over UDS, rollover) is described in
  [KEY_MANAGEMENT_DESIGN.md](KEY_MANAGEMENT_DESIGN.md); key validity periods
  and in-vehicle key distribution are not implemented.
- SecOC is integrated in the Ethernet gateway. The S2S and diagnostic paths do
  not use it; diagnostics are protected by UDS SecurityAccess/Authentication
  in the ECUs.
- The software crypto provider is for the bench only. It is not hardened
  against side channels beyond the constant-time MAC comparison.
