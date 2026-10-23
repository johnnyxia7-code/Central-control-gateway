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
| CAN / CAN FD | AUTOSAR profile 1 "24Bit-CMAC-8Bit-FV" (64-bit counter, 8 LSBs sent, 24-bit MAC, 2 verify attempts) | 4 bytes |
| Ethernet | full 64-bit counter, 64-bit MAC, acceptance window 1000 | 16 bytes |

## 3. Freshness value management

A counter-based freshness value manager (`secoc::FreshnessManager`) keeps one
Tx and one Rx counter per Data ID.

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
- **Persistence:** counters must survive a reset, otherwise a reused value
  would make old messages valid again. The gateway process saves a snapshot to
  `--fv-store` every 10 s and on exit. On start-up the Tx counters are restored
  with a margin of 10 000, so a value sent after the last snapshot is never
  sent again. The file is written to `.tmp` first and then renamed.

| Attack | Result |
|--------|--------|
| Payload changed | `VERIFICATION_FAILURE` (MAC) |
| Forged with a wrong key | `VERIFICATION_FAILURE` |
| MAC copied to another PDU | `VERIFICATION_FAILURE` (Data ID is part of the MAC) |
| Replay, full FV transmitted | `FRESHNESS_FAILURE` |
| Replay, truncated FV | `VERIFICATION_FAILURE` (the FV is rebuilt into the next epoch, so the MAC no longer matches) |
| Counter far ahead of the window | `FRESHNESS_FAILURE` |

## 4. Gateway integration (`ccg_ethgw`)

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

## 5. Crypto service

`secoc::ICryptoService` corresponds to the AUTOSAR Csm and works with key slots
(`hasKey`, `generateMac`):

| Implementation | Use | Key source |
|----------------|-----|------------|
| HSM driver (target) | series vehicles | keys provisioned at end of line or by OTA key management; they never leave the HSM |
| `SoftwareCryptoService` | bench, simulation, tests | `--keys FILE` (`KEY_ID=<32 hex digits>` per line) or `--demo-keys` (built-in **test keys**, bench only) |

The software AES-128 / CMAC (`ccg/crypto/aes_cmac.hpp`) has no dependencies and
is verified against:
- FIPS-197 and SP 800-38A AES known answers,
- RFC 4493 CMAC examples 1–4 (including the subkeys),
- OpenSSL 3 for 201 random keys and messages (test-only, built when OpenSSL is found).

MAC comparison runs in constant time over the truncated bits.

The gateway refuses to start (`RoutingConfigError`) if a secured PDU's key is
not available.

## 6. Reference configuration

| PDU | Bus | Role | Profile | Key | Data ID | Length (authentic + trailer) |
|-----|-----|------|---------|-----|---------|------------------------------|
| ADAS_SteerTorqueReq | ETH_ADAS 0x1003 | received | Ethernet | K_ADAS_GW | 0x1003 | 8 + 16 |
| GW_SteerTorqueReq | CHS_CAN 0x1B0 | assembled, on update | profile 1 | K_GW_CHS | 0x01B0 | 4 + 4 |
| VCU_PowerLimit | PT_CAN 0x130 (FD) | received | profile 1 | K_VCU_GW | 0x0130 | 12 + 4 |
| VCU_PowerLimit_ADAS | ETH_ADAS 0x130 | message routing target | Ethernet | K_GW_ADAS | 0x2130 | 12 + 16 |

```
ccg_eth_gateway --bind ... --keys /etc/ccg/secoc.keys --fv-store /var/lib/ccg/freshness
ccg_eth_gw_sim     # genuine stream, tampered request, replay, timeout -> safe state
```

## 7. Limitations / next steps

- Counter-based freshness only. A global freshness master (trip/reset counter
  with synchronisation messages, AUTOSAR "FVM" / JASPAR profile 3) and
  timestamp-based freshness are not implemented.
- No secured I-PDU header (dynamic length) and no secured container PDUs. The
  authentic part has a fixed length.
- No key management. Key update (e.g. via UDS 0x31/0x2E into the HSM) and key
  validity periods are out of scope.
- SecOC is integrated in the Ethernet gateway. The S2S and diagnostic paths do
  not use it; diagnostics are protected by UDS SecurityAccess/Authentication
  in the ECUs.
- The software crypto provider is for the bench only. It is not hardened
  against side channels beyond the constant-time MAC comparison.
