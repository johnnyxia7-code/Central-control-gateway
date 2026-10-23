# HPC Gateway – SecOC key management

## 1. Purpose

SecOC (see [SECOC_DESIGN.md](SECOC_DESIGN.md)) is only as strong as its keys.
The key manager of the gateway (`ccg_keym`):

- holds the SecOC keys and the FV master key in **SHE key slots** and serves
  them to SecOC as its crypto service (MAC generation and verification),
- accepts **key updates only in the SHE memory update protocol**: the key is
  encrypted and authenticated by the backend key server, never visible on the
  bus or to the tester, and every update is confirmed with a cryptographic proof,
- protects the slots against **rollback** (update counter), **unauthorised
  updates** (MASTER_ECU_KEY authorisation, UID binding, write protection) and
  **brute force** (lockout),
- renews keys in a vehicle **without breaking communication**: staged
  activation, then a grace period in which the previous key is still accepted,
- offers all this as UDS routines on the gateway's own DoIP address,
- acts as **in-vehicle key master**: generates the SecOC keys it shares with
  the CAN ECUs and distributes them with the same SHE protocol over ISO-TP
  (section 7).

```
 Backend key server                 HPC central gateway                         ECUs
 (owns MASTER_ECU_KEY)
        |   DoIP / UDS 0x31 F200          +----------------------------+
        |   M1 | M2 | M3  ------------->  | KeyManagementService       |
        |   <-------------  M4 | M5       |   (ILocalServiceHandler)   |
        |                                 |          |                 |
        |   31 01 F201 (activate) ------> | KeyManager (KeyM + HSM)    |
        |                                 |  slot | active | pending | previous
        |                                 |          | ICryptoService  |
        |                                 | SecOC / FV master (ccg_ethgw) ---> secured PDUs
        +---------------------------------+----------------------------+
```

## 2. Key slots

| Slot (SHE ID) | Key ID | Use | Authorised by |
|---------------|--------|-----|---------------|
| MASTER_ECU_KEY (0x1) | – | authorises key updates, never used for MACs | MASTER_ECU_KEY |
| KEY_1 (0x4) | K_ADAS_GW | ADAS → gateway (ETH_ADAS) | MASTER_ECU_KEY or KEY_1 |
| KEY_2 (0x5) | K_GW_ADAS | gateway → ADAS (re-authentication) | MASTER_ECU_KEY or KEY_2 |
| KEY_3 (0x6) | K_VCU_GW | VCU → gateway (PT_CAN) | MASTER_ECU_KEY or KEY_3 |
| KEY_4 (0x7) | K_GW_CHS | gateway → chassis (CHS_CAN) | MASTER_ECU_KEY or KEY_4 |
| KEY_5 (0x8) | K_FV_MASTER | FV synchronisation messages | MASTER_ECU_KEY or KEY_5 |
| KEY_10 (0xD) | K_KEY_MASTER | vehicle key master secret (section 7); a cipher key, never usable as MAC key | MASTER_ECU_KEY or KEY_10 |

Every stored key has a **28-bit update counter** (its generation) and the SHE
protection flags:

| Flag | Effect in the key manager |
|------|---------------------------|
| WRITE_PROTECTION | slot can never be updated again (`ERC_KEY_WRITE_PROTECTED`) |
| KEY_USAGE | 1 = MAC key. SecOC refuses keys without it (`hasKey` is false) |
| WILDCARD | update with the wildcard UID (all zero) is forbidden |
| BOOT_PROTECTION, DEBUGGER_PROTECTION | stored and reported; enforced by the HSM on the target |

Gateway UID: `00 00 00 00 00 00 00 43 43 47 00 00 00 00 01` (reference configuration).

## 3. SHE memory update protocol (`keym::she`)

```
M1 = UID (120 bit) | KeyID (4) | AuthID (4)
M2 = AES-CBC(K1, IV = 0)( Counter (28) | Flags (5) | 0 (95) | NewKey (128) )
M3 = AES-CMAC(K2, M1 | M2)
M4 = M1 | AES-ECB(K3)( Counter (28) | 1 | 0 (99) )
M5 = AES-CMAC(K4, M4)

K1 = KDF(AuthKey, KEY_UPDATE_ENC_C)    K2 = KDF(AuthKey, KEY_UPDATE_MAC_C)
K3 = KDF(NewKey,  KEY_UPDATE_ENC_C)    K4 = KDF(NewKey,  KEY_UPDATE_MAC_C)
KDF(K, C) = AES-MP(K | C)              (Miyaguchi-Preneel compression)
KEY_UPDATE_ENC_C = 01015348 45008000 00000000 000000B0
KEY_UPDATE_MAC_C = 01025348 45008000 00000000 000000B0
```

Checks of `KeyManager::loadKey` (SHE CMD_LOAD_KEY), in this order:

| Check | Error code |
|-------|------------|
| key updates locked after repeated authentication failures | `ERC_BUSY` (UDS NRC 0x37) |
| target slot configured; AuthID = MASTER_ECU_KEY, or = KeyID for KEY_n | `ERC_KEY_INVALID` |
| authorising key present | `ERC_KEY_EMPTY` |
| target not write-protected | `ERC_KEY_WRITE_PROTECTED` |
| M3 correct (CMAC with K2) | `ERC_KEY_UPDATE_ERROR` (counts towards the lockout) |
| UID = gateway UID, or wildcard and the key allows it | `ERC_KEY_UPDATE_ERROR` |
| counter > counter of the active and of the pending key (anti-rollback) | `ERC_KEY_UPDATE_ERROR` |

On success the gateway returns M4/M5, computed from the new key and its own UID
(also for a wildcard update). The backend compares them with its own
computation: only a device that really decrypted and stored the key can answer
correctly. `ccg_key_tool` is the bench version of the backend.

The implementation reproduces the SHE specification example (UID …01, KEY_1,
MASTER_ECU_KEY 000102…0F, new key 0F0E…00, counter 1) bit for bit, and a second
vector with flags and a large counter cross-checked with OpenSSL.

## 4. Key generations and rollover

```
                 loadKey (staged slot)            activatePending()                grace period over
  active: gen 1 ------------------------> active: gen 1   -------------> active:   gen 2  ------------> active: gen 2
                                          pending: gen 2                  previous: gen 1
  Tx MAC:  gen 1                          gen 1                           gen 2                          gen 2
  Rx MAC:  gen 1                          gen 1, gen 2                    gen 2, gen 1                   gen 2
```

- A SecOC key is shared by sender and receiver(s); the ECUs receive their
  copy in their own SHE update, at different times. The gateway therefore
  **stages** a new key as *pending* and keeps transmitting with the active key.
- The backend activates the new generation (`31 01 F201`) once all ECUs
  confirmed it with M4/M5. From then on the gateway transmits with the new key.
- **Verification** (`ICryptoService::verifyMac`, AUTOSAR Csm_MacVerify) accepts
  the active key, the *previous* key during the grace period (sender has not
  switched yet) and the *pending* key (sender switched earlier). Such
  verifications are counted (`rolloverVerifications`).
- After the grace period (10 min in the reference configuration) the previous
  key is deleted (`PREVIOUS_KEY_EXPIRED`). A leaked old key no longer works.
- MASTER_ECU_KEY is not staged: it is replaced at once.
- An empty slot is filled directly (nothing to roll over).
- `31 01 F202` discards pending keys (aborted campaign).

Freshness values continue across a key change; they are not reset.

## 5. UDS interface (`KeyManagementService`)

Registered on the diagnostic gateway with `DiagGateway::addLocalService`; it
answers on the gateway's own logical address (0x1001).

| Request | Response | Notes |
|---------|----------|-------|
| `22 F2 A0` | `62 F2 A0 n {slot, state, counter (4), pending counter (4)}` | any session; state bits: 01 active, 02 pending, 04 previous, 08 write-protected, 10 MAC key |
| `31 01 F2 00 M1 M2 M3` (68 bytes) | `71 01 F2 00 <SHE error code> [M4 M5]` | extended session, physical only |
| `22 F2 A1` | `62 F2 A1 <SHE UID, 15 bytes>` | any session; needed to address an update container |
| `31 01 F2 01 [slot ..]` | `71 01 F2 01 <number of keys activated>` | all pending keys or only the listed slots; NRC 0x24 if none is pending |
| `31 01 F2 02 [slot ..]` | `71 01 F2 02 <number of keys discarded>` | as above |
| `31 01 F2 10 [group ..]` | `71 01 F2 10 00` | key master: start a campaign (section 7) |
| `31 03 F2 10` | `71 03 F2 10 <state> <n> {result, generation (4), ECU (2), SHE error}` | key master: results |

Negative responses: 0x7F wrong session, 0x13 length, 0x12 sub-function (only
startRoutine), 0x31 unknown routine, 0x37 lockout (3 authentication failures
→ 10 s), 0x72 key store could not be written. Functional requests never reach
the key routines.

The routines are not behind SecurityAccess: their authorisation is the SHE
protocol itself (M3 needs MASTER_ECU_KEY, which only the backend has), and the
outcome is reported as the SHE error code so the backend can tell an
authentication failure from a rollback.

**Persistence before confirmation**: the service writes the key store before
it returns M4/M5 or the activation result. If that fails it answers NRC 0x72 and
the backend retries with the next counter value.

## 6. Security events

`KeyManager::events()` (latest 64, `eventCount()` total) for the IdsM:
`PROVISIONED`, `KEY_LOADED`, `KEY_STAGED`, `UPDATE_REJECTED` (with SHE error
code), `UPDATE_LOCKED`, `KEY_ACTIVATED`, `PENDING_DISCARDED`,
`PREVIOUS_KEY_EXPIRED`. MAC failures of SecOC PDUs remain SecOC security events
of the Ethernet gateway.

## 7. In-vehicle key master (`keym::KeyMaster`)

The gateway renews the SecOC keys it shares with CAN ECUs itself; the backend
only triggers the campaign and reads its results.

**ECU authorisation keys.** Each ECU's MASTER_ECU_KEY is derived from the
vehicle key master secret (gateway KEY_10) and the ECU's SHE UID:

```
MASTER_ECU_KEY(ECU) = KDF(K_KEY_MASTER, UID | 'M')        KDF = AES-MP as in section 3
```

The plant provisions every ECU with its derived key (the backend knows the
secret); the gateway derives it inside its HSM when it needs it. One ECU's
key reveals nothing about the others.

**Key groups** (`config/vehicle_key_master.cpp`): one SecOC key and every slot
holding it.

| # | Key | Gateway slot | ECU slots |
|---|-----|--------------|-----------|
| 0 | K_VCU_GW | KEY_3 | VCU 0x0010 KEY_1 |
| 1 | K_GW_CHS | KEY_4 | EPS 0x0021 KEY_1 |
| 2 | K_FV_MASTER | KEY_5 | VCU KEY_2, EPS KEY_2, BCM 0x0030 KEY_1 |

The ADAS keys stay with the backend (DoIP-native ECU on Ethernet).

**Campaign** (started with `31 01 F210 [group ..]` or `KeyMaster::start`):

```
1 prepare    per ECU   10 03, 22 F2A1 (UID), 22 F2A0 (stored generations)
2 load       per group new key from the HSM RNG, generation = newest generation of any member + 1,
                       staged in the gateway HSM (stageInternal);
             per member 10 03, 31 01 F200 M1 M2 M3 (authorised by the derived MASTER_ECU_KEY),
                       M4/M5 checked against the expected proof
3 activate   per ECU   10 03, 31 01 F201 <slots of complete groups>, 31 01 F202 <slots of failed groups>
             gateway   activate complete groups, discard failed ones (last, see below)
```

- **Atomic per group**: a key is activated only when every member proved
  (M4/M5) that it stores it. A failed member (no response, negative response,
  SHE error, wrong proof) fails the group, and the members that already hold
  the key discard it. Other groups go ahead.
- **Activation order**: ECUs first, the gateway last. During the switch,
  receivers accept the pending and the previous key (section 4), so no PDU is
  lost whichever side switches first. If an ECU does not confirm the
  activation, the group is reported `ACTIVATION_FAILED` but the gateway still
  activates. The ECU keeps verifying with its pending key, and the next
  campaign replaces it.
- **Results** per group: `ACTIVATED`, `ECU_UNREACHABLE`, `ECU_REFUSED`,
  `KEY_REJECTED` (with the ECU's SHE error code), `PROOF_MISMATCH`,
  `GATEWAY_KEY_ERROR`, `ACTIVATION_FAILED`, `NOT_RUN`; plus the generation and
  the ECU that failed. A failed group simply runs again in a later campaign
  (e.g. at the next ignition when the ECU is powered).
- **Diagnostic client**: the requests use the gateway's own ISO-TP channels
  (`diag::IDiagClient`, implemented by `DiagGateway`). While the key master
  talks to an ECU, tester requests to that ECU are refused with a diagnostic
  NACK. P2 is 1 s, and 5.5 s after NRC 0x78.
- **Key generation**: `keym::IRandom`. The Linux process uses `getrandom()`
  (`platform::SystemRandom`) and the target uses the HSM TRNG.
  `DeterministicRandom` is for tests and simulation only.

```
ccg_key_master_sim   # EPS unpowered: K_VCU_GW renewed, EPS groups discarded everywhere;
                     # EPS powered: remaining groups renewed; SecOC and FV sync never break
```

## 8. Bench processes

```
# diagnostic gateway owns the key store (first start: --demo-keys provisions TEST keys)
# and runs the key master (31 01 F210); new gateway keys reach ccg_eth_gateway via the store
ccg_diag_gateway --can PT_CAN=can0 --can CHS_CAN=can1 --can BODY_CAN=can2 \
                 --key-store /var/lib/ccg/keys --demo-keys

# Ethernet gateway follows it: reloads the key store when it changes
ccg_eth_gateway --bind ... --key-store /var/lib/ccg/keys --fv-store /var/lib/ccg/freshness

# backend: build M1..M3 for KEY_3, send "UDS ..." with any DoIP tester, check the answer
ccg_key_tool --uid 000000000000004343470000000001 --slot 6 --auth-slot 1 \
             --auth-key <MASTER_ECU_KEY> --key <new key> --counter 2 [--check <response>]

ccg_keym_sim      # forged and replayed containers, update, activation, rollover, retired key
ccg_key_master_sim  # gateway as key master distributing keys to VCU, EPS, BCM
```

Key store file (mode 0600, written to a temporary file, `fsync`ed, renamed):

```
active   <slot> <counter> <flags hex> <key hex>
pending  <slot> <counter> <flags hex> <key hex>
previous <slot> <counter> <flags hex> <key hex> <remaining grace period ms>
```

## 9. Limitations / next steps

- On the target the key slots, SHE protocol and counters live in the HSM
  (keys never in application memory); the software key manager and the
  key store file are the bench stand-in. Production (EOL) provisioning of
  MASTER_ECU_KEY is a plant process; `provision()` models it.
- Key master: the campaign runs the ECUs one after the other (one request in
  flight), and its results are not persisted across a restart. Generation
  numbers of discarded (never activated) keys can be used again by the next
  campaign. The key master does not unlock ECUs with SecurityAccess, because
  the SHE container is the authorisation.
- No key validity period / automatic renewal schedule; the backend decides when
  to renew.
- The two Linux processes share the key store through a file (single writer:
  the diagnostic gateway). A target uses one HSM shared by both.
