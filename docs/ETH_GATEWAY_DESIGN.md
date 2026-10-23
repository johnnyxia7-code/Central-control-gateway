# HPC Central Ethernet Gateway – Routing, Frame Decomposition and Assembly

## 1. Purpose

The central gateway on the HPC connects the domain CAN buses with the Ethernet
backbone (ADAS domain controller, IVI) and the CAN buses with each other. It
provides four functions:

| Function | What happens | Example in the reference table |
|----------|--------------|--------------------------------|
| **Message routing** | A received PDU is forwarded unchanged to one or more target PDUs, optionally with a new identifier and padding. Supported paths: CAN↔CAN, CAN↔Ethernet, Ethernet↔Ethernet. | `ESP_WheelSpeeds` CHS_CAN → PT_CAN + ETH_ADAS; `ADAS_LatCtrlReq` ETH_ADAS 0x1001 → CHS_CAN 0x1A1 |
| **Signal routing** | Single signals are moved from a received PDU into a PDU that the gateway sends, either as a raw copy or rescaled to the target scaling. | `VCU_VehSpd` (0.01 km/h) → `GW_VehSpd` (0.1 km/h) |
| **Frame decomposition** | A received frame is split up: its signals go to different target frames, and a received UDP datagram is split into its contained PDUs. | `BCM_Status` → `GW_VehicleState` (CHS_CAN) + `GW_BodyInfo` (PT_CAN) + `GW_ADAS_VehicleInfo` (ETH_ADAS) |
| **Frame assembly** | The gateway builds new frames from signals of several source frames, and packs several PDUs into one UDP datagram. | `GW_ADAS_VehicleInfo` from ESP + VCU + BCM; ETH_ADAS datagram with `0xB0`, `0x120` and `0x2001` |

```
  PT_CAN (FD) ─┐                                             ┌─ ETH_ADAS (UDP, SoAd PDU header)
  CHS_CAN ─────┤   Rx ──► message routing ──► Tx CAN / Ethernet container ──┤
  BODY_CAN ────┘     └──► signal routing ──► assembled PDUs ─┘   └─ ETH_IVI
                         (E2E check, timeout,   (cyclic / on-change,
                          invalid propagation)   MDT, E2E protect)
```

## 2. Ethernet framing (SoAd PDU header)

PDUs on an Ethernet channel travel in UDP datagrams using the AUTOSAR SoAd
"PDU header" layout. Each PDU carries an 8-byte header:

```
 0               4               8
 +---------------+---------------+------------------+---------------+---------------+-----
 | Header ID (32)| Length (32)   | payload (Length) | Header ID     | Length        | ...
 +---------------+---------------+------------------+---------------+---------------+-----
```

- **Assembly (Tx):** each Ethernet channel has one transmit container. The first
  PDU starts the `collectionTimeout`; PDUs queued until then share the datagram.
  The container is sent early when the next PDU would exceed `maxDatagramSize`
  (sent first, then the new PDU starts a new datagram), or right away for an
  `urgent` PDU or a channel with timeout 0.
- **Decomposition (Rx):** the datagram is split into PDUs and each is looked up
  by (channel, header ID). Unknown IDs are skipped by their length and counted
  as `unroutedPdus`. If a header is cut off, or announces more bytes than the
  datagram holds, `malformedDatagrams` is counted. The PDUs before the defect
  are still routed.
- `maxDatagramCollectionDelay` records the longest time a PDU waited in a container.

## 3. Processing

### 3.1 Reception

```
onCanFrame(channel, frame) / onEthernetDatagram(channel, bytes)
  └─ lookup (channel, id, extended) ─ none ─► unroutedPdus
       └─ length < configured length ─► lengthErrors (dropped)
            ├─ message routing: forward to every target PDU   (always, unchanged)
            └─ signal routing:
                 E2E check (if configured) ─ fail ─► data not used, debounce
                 refresh deadline, extract signals, convert, write target signals
                 evaluate target PDUs (trigger / change)
```

**E2E stays end-to-end.** The gateway forwards routed PDUs unchanged, including
CRC and counter, and never re-protects them. A PDU-route target with an E2E
configuration is rejected. Signal routing does check E2E, because it ends the
protection: a frame that fails the check is not used. After
`maxConsecutiveErrors` failures in a row the routes' substitution values are applied.

### 3.2 Signal conversion

| Case | Target raw value |
|------|------------------|
| source raw == source SNA pattern | target SNA pattern (or init value if the target has none) |
| `Conversion::Raw` | source raw copied (equal length and signedness required) |
| `Conversion::Physical` | `physicalToRaw(target, rawToPhysical(source))`, rounded and saturated |

### 3.3 Source faults

When a source PDU misses its deadline (`timeout`, monitored from start-up) or
fails E2E after the debounce, every route from it applies its `Substitution`:

| Substitution | Target value |
|--------------|--------------|
| `HoldLast` | unchanged |
| `InitValue` | target signal init value |
| `InvalidValue` | target SNA pattern (validated to exist) |

The first good frame afterwards restores normal routing. After a counter jump
the E2E receiver resynchronises on one frame first.

### 3.4 Transmission of assembled PDUs

| `TxMode` | Sent when |
|----------|-----------|
| `OnUpdate` | a triggering source signal was received |
| `OnChange` | a triggering source signal changed the target content |
| `Cyclic` | every `cycleTime` |
| `CyclicAndOnChange` | every `cycleTime`, plus immediately on change |

- Routes with `triggering = false` update the content silently. The new value
  goes out with the next triggered or cyclic frame (e.g. outside temperature).
- `minDelay` (MDT) spaces two frames of the same PDU. Frames it holds back are
  delayed, never dropped.
- An E2E configuration on an assembled PDU means a fresh counter and CRC in every frame.
- Routed (forwarded) PDUs are sent at once, without MDT, to keep routing latency minimal.

## 4. Configuration (`ccg::ethgw::RoutingConfig`)

```
Channel       name, BusType {Can, CanFd, Ethernet}, collectionTimeout, maxDatagramSize
PduDefinition name, channel, id (CAN ID / header ID), extended, fd, length, signals, e2e,
              timeout (Rx), txMode, cycleTime, minDelay, padding, urgent (Tx)
PduRoute      source PDU -> target PDUs
SignalRoute   source pdu.signal -> target pdu.signal, Conversion, Substitution, triggering
```

`validateRoutingConfig()` runs in the `EthernetGateway` constructor and
rejects the table (`RoutingConfigError`) on:

- unknown channels / PDUs / signals, duplicate names, duplicate identifiers per channel
- CAN ID range, classic length ≤ 8, CAN FD lengths (12, 16, … 64) only on CAN FD
  channels, Ethernet PDU + header ≤ `maxDatagramSize`
- signal layout: fits the PDU, no overlap incl. E2E CRC/counter (shared with the S2S validator)
- **routing loops:** a PDU that is both received and transmitted, or a PDU routed to itself
- a target written by more than one PDU route, or by a PDU route and signal routes
- a target signal written by more than one signal route
- a target shorter than its source, or E2E on a PDU-route target
- a raw copy between signals of different length/signedness; `InvalidValue` without an SNA pattern
- an assembled PDU that would never be sent (no cycle and no triggering route)

## 5. Reference routing table (`config/vehicle_eth_gateway_matrix.cpp`)

### Channels

| # | Channel | Type | Container |
|---|---------|------|-----------|
| 0 | PT_CAN | CAN FD | – |
| 1 | CHS_CAN | CAN | – |
| 2 | BODY_CAN | CAN | – |
| 3 | ETH_ADAS | Ethernet | 5 ms collection, 1400 B |
| 4 | ETH_IVI | Ethernet | 10 ms collection, 1400 B |

### Message routing

| Source | Targets |
|--------|---------|
| ESP_WheelSpeeds CHS_CAN 0x0B0 (8 B) | PT_CAN 0x0B0 (classic frame on FD bus), ETH_ADAS 0x0B0 |
| VCU_DriveState PT_CAN 0x120 (FD, 16 B, E2E) | ETH_ADAS 0x120, ETH_IVI 0x120 |
| ADAS_LatCtrlReq ETH_ADAS 0x1001 (8 B) | CHS_CAN **0x1A1** (ID translation) |
| ADAS_HmiInfo ETH_ADAS 0x1002 (32 B) | ETH_IVI 0x1002 |

### Signal routing / assembled PDUs

| Target PDU | Tx | Signals ← source |
|------------|----|------------------|
| GW_VehicleState CHS_CAN 0x3E0, E2E | 100 ms + on change, MDT 10 ms | GW_VehSpd ← VCU_VehSpd (physical 0.01→0.1 km/h), GW_GearPos ← VCU_GearPos, GW_ReadySts ← VCU_ReadySts, GW_IgnState ← BCM_IgnState, GW_OutsideTemp ← BCM_OutsideTemp (non-triggering, hold last) |
| GW_BodyInfo PT_CAN 0x2A8 | on change, MDT 20 ms | GW_IgnState, GW_DoorOpenAny, GW_HazardSts ← BCM_Status |
| GW_ADAS_VehicleInfo ETH_ADAS 0x2001 (16 B) | 20 ms cyclic | 4 wheel speeds ← ESP (physical 0.03125→0.01 km/h), VehSpd, GearPos, AccelPedal ← VCU, IgnState ← BCM |

## 6. Integration

```
ccg_eth_gateway --bind PT_CAN=can0 --bind CHS_CAN=can1 --bind BODY_CAN=can2 \
                --bind ETH_ADAS=udp:30500:192.168.10.20:30500 \
                --bind ETH_IVI=udp:30501:192.168.10.30:30501 [--period-ms 1]
```

- Every channel must be bound: a CAN channel to a SocketCAN interface (CAN FD
  enabled for FD channels), an Ethernet channel to a point-to-point UDP socket
  connection.
- Kernel CAN filters only pass identifiers the gateway routes.
- One `poll()` loop; `mainFunction()` every 1 ms, so the container collection
  timeouts are kept to ±1 ms.
- `ccg_eth_gw_sim` replays a 300 ms scenario in virtual time.

## 7. Limitations / next steps

- No transport-protocol segmentation (ISO-TP / SOME/IP-TP); PDUs longer than
  the target bus allows are rejected by the validator.
- Ethernet framing is SoAd PDU header over UDP only; IEEE 1722 ACF-CAN and TCP
  socket connections are not implemented.
- No SecOC, no VLAN/QoS configuration. Diagnostic routing (DoIP ↔ UDS on CAN) is a separate function, see `DIAG_GATEWAY_DESIGN.md`.
- No Tx queue for a busy CAN controller: a failed transmission is counted
  (`canTxFailures`), not retried.
- The routing table is written by hand; a series project generates it from the communication matrix.
