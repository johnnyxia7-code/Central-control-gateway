# HPC Gateway – Signal-to-Service (S2S) Function

## 1. Purpose

In a zonal / central E/E architecture the HPC (high performance computer) is the
boundary between the signal-oriented CAN world (ESP, EPS, BCM, BMS, …) and the
service-oriented Ethernet world (SOME/IP applications on the HPC, ADAS domain,
IVI, cloud connector). The S2S function performs the translation in both
directions:

| Direction | Source | Target |
|-----------|--------|--------|
| Signal → Service | CAN Rx PDU signals | SOME/IP event, field notifier, field getter |
| Service → Signal | SOME/IP method call (request / fire&forget) | CAN Tx PDU signals |

```
          CAN / CAN FD                         S2S gateway (this repo)                     Ethernet
 ┌─────┐                    ┌──────────────────────────────────────────────────────┐
 │ ESP ├──0x0FD (E2E)──┐    │  Rx: ID filter → DLC check → E2E check → decode       │
 │ EPS ├──0x0A5 (E2E)──┤    │      → validity (SNA / range) → signal state           │   NOTIFICATION
 │ BCM ├──0x2F0 ───────┼───►│      → deadline monitoring → status per element       ├──► 0x6001.0x8001 …
 │ BMS ├──0x3C0 ───────┘    │  Event engine: on-change / cyclic / debounce,         │
 └─────┘                    │      field cache, getter, initial event on subscribe  │   REQUEST/RESPONSE
 ┌─────┐                    │  Method engine: deserialize → range check →           │◄──► 0x6002.0x0010 …
 │ BCM │◄─0x3A0 (E2E)──┐    │      all-or-nothing signal write → Tx trigger          │
 │ HVAC│◄─0x3A1 ───────┴────┤  Tx: burst repetitions / cyclic / MDT / pulse reset   │
 └─────┘                    │      → E2E protect → CAN                              │
                            └──────────────────────────────────────────────────────┘
```

## 2. Architecture

```
include/ccg/
  can/signal_codec.hpp      DBC compliant Intel/Motorola bit codec, factor/offset, saturation
  e2e/can_e2e.hpp           CRC-8 SAE J1850 + 4-bit alive counter (AUTOSAR E2E Profile 1 style)
  someip/someip_message.hpp SOME/IP header, return codes, big-endian payload (de)serializer
  s2s/s2s_config.hpp        S2S mapping model + validateConfig()
  s2s/transport.hpp         ICanTransmitter / ISomeIpBinding (lower layer abstraction)
  s2s/s2s_gateway.hpp       S2SGateway runtime
config/vehicle_s2s_matrix.* reference communication matrix (normally generated)
platform/linux/             SocketCAN adapter, SOME/IP-over-UDP binding (static SD)
app/                        ccg_s2s_gateway (Linux process), ccg_s2s_sim (virtual-time bench)
```

The core (`ccg_s2s`) has no OS dependency and no dynamic allocation in the CAN
Rx hot path apart from payload building. It is single threaded by design: all
entry points (`onCanFrame`, `onSomeIpRequest`, `onSubscribe`, `mainFunction`)
are called from one executor, which avoids locks and makes timing deterministic.
Time is passed in explicitly (`TimePoint now`), so the same code runs on the
target, in the simulator and in unit tests.

## 3. Signal → Service

### 3.1 Reception pipeline (`onCanFrame`)

1. **ID filter** – frames not in the S2S matrix are counted (`canRxUnknownId`) and ignored
   (they belong to classic CAN-to-CAN routing). On Linux the kernel filter
   (`CAN_RAW_FILTER`) already removes them.
2. **Length check** – a frame shorter than the configured PDU length is discarded (`canRxLengthError`).
3. **E2E check** (if configured):
   - `CRC_ERROR` / `WRONG_SEQUENCE` → frame discarded; after `maxConsecutiveErrors`
     consecutive errors all signals of the PDU get status `E2E_ERROR`.
   - `REPEATED` → stale frame discarded.
   - `OK` / `OK_SOME_LOST` (counter jump ≤ `maxDeltaCounter`) → accepted.
   - After a counter jump the receiver resynchronises on the next frame.
4. **Decode** every signal (DBC bit layout), compute physical value.
5. **Validity** – raw == SNA pattern (`invalidRaw`) or physical value outside
   `[min, max]` (± ½ LSB) → `INVALID`. Valid values update `lastValidRaw`.
6. **Deadline** – `lastRx` is refreshed, timeout and E2E fault are cleared.
7. All events using a signal of this PDU are re-evaluated (on-change).

### 3.2 Signal status

Every element is followed by a `uint8` status when `appendStatus` is set
(default), so that consumers never confuse a substitute value with real data:

| Value | Status | Cause | Precedence (1 = wins) |
|------:|--------|-------|---------------------:|
| 0 | `VALID` | – | 5 |
| 1 | `INVALID` | SNA pattern / out of range | 4 |
| 2 | `TIMEOUT` | no frame for `timeout` (monitoring starts at start-up) | 2 |
| 3 | `E2E_ERROR` | `maxConsecutiveErrors` E2E failures in a row | 1 |
| 4 | `NOT_AVAILABLE` | nothing received since start-up (and deadline not yet expired) | 3 |

For non-valid elements a **substitution** is applied per element:
`InitValue` (default), `HoldLastValid` or `Constant`.

### 3.3 Update modes

| Mode | Behaviour |
|------|-----------|
| `OnChange` | Notification when the serialized payload (values **and** statuses) changes. `minInterval` debounces: a change inside the interval is held back and the *latest* value is sent when the interval has elapsed. |
| `Cyclic` | Notification every `cycleTime`, independent of reception (statuses show staleness). |
| `OnChangeAndCyclic` | Both; typical for slowly changing fields (heart-beat + change). |

Fields additionally provide:
- **Getter** (`getterMethodId`) – synchronous RESPONSE with the current payload.
- **Initial event** – on `onSubscribe` the current value is sent unicast to the new subscriber.

## 4. Service → Signal

### 4.1 Request handling (`onSomeIpRequest`)

Checks in SOME/IP order, each producing the specified return code in an
`ERROR` message (only for `REQUEST`; `REQUEST_NO_RETURN` is never answered):

| Check | Return code |
|-------|-------------|
| Protocol version ≠ 1 | `E_WRONG_PROTOCOL_VERSION` (0x07) |
| Service / instance not offered | `E_UNKNOWN_SERVICE` (0x02) |
| Interface version ≠ major version | `E_WRONG_INTERFACE_VERSION` (0x08) |
| Method / getter ID unknown | `E_UNKNOWN_METHOD` (0x03) |
| Request type ≠ configured call semantics | `E_WRONG_MESSAGE_TYPE` (0x0A) |
| Payload too short / invalid boolean | `E_MALFORMED_MESSAGE` (0x09) |
| Argument outside the CAN signal range or equal to SNA | `E_NOT_OK` (0x01) |

Trailing payload bytes are tolerated (forward compatibility with newer minor
versions). Arguments are written **all-or-nothing**: if one argument fails,
no signal is changed and no frame is sent. Response header copies client ID and
session ID of the request.

### 4.2 Transmission

| Parameter | Meaning |
|-----------|---------|
| `cycleTime` | periodic frame (0 = none) |
| `eventRepetitions` | frames sent when a method writes the PDU (0 = only with next cyclic frame) |
| `repetitionInterval` | spacing of the burst frames |
| `minDelay` | minimum delay time (MDT) between two frames of the PDU; blocked frames are postponed, not dropped |
| `pulse` (argument) | request semantics: the signal falls back to its init value after the burst (or the next cyclic frame) – e.g. `HPC_CentralLockReq` |

E2E-protected Tx PDUs get a new alive counter and CRC for every transmitted frame.

## 5. Reference matrix (`config/vehicle_s2s_matrix.cpp`)

### CAN Rx

| PDU | ID | Cycle / timeout | E2E | Signals |
|-----|----|-----------------|-----|---------|
| ESP_VehicleSpeed | 0x0FD | 10 / 50 ms | DataID 0x00FD | VehSpd 0.01 km/h, LongAccel 0.001 m/s² (signed), YawRate 0.01 °/s (signed) |
| EPS_SteeringAngle | 0x0A5 | 10 / 50 ms | DataID 0x00A5 | SteerWhlAng 0.1° (Motorola, signed), SteerWhlSpd 1 °/s (Motorola) |
| BCM_DoorStatus | 0x2F0 | 100 / 500 ms | – | 4 doors + trunk (closed/ajar/open), central lock state |
| BMS_PackStatus | 0x3C0 | 100 / 500 ms | – | SoC 0.1 %, PackVolt 0.1 V, PackCurr 0.05 A (signed) |

### CAN Tx

| PDU | ID | Transmission | E2E | Signals |
|-----|----|--------------|-----|---------|
| HPC_BodyCommand | 0x3A0 | 100 ms cyclic + 3× burst @ 20 ms, MDT 10 ms | DataID 0x03A0 | CentralLockReq (pulse), TrunkOpenReq (pulse) |
| HPC_ClimateCommand | 0x3A1 | 200 ms cyclic + 1 immediate frame, MDT 10 ms | – | CabinTempSetpt (0.5 °C, offset 10), FanLevel |

### Services

| Service | ID | Element | ID | Type | Update | Elements / arguments |
|---------|----|---------|----|------|--------|----------------------|
| VehicleMotionService | 0x6001 | VehicleDynamics | 0x8001 (EG 1) | event | cyclic 20 ms | speed, accel, yaw rate (float32 + status) |
| | | SteeringWheel | 0x8002 (EG 2), getter 0x0001 | field | on-change, min 20 ms | angle (hold last valid), speed |
| BodyService | 0x6002 | DoorStatus | 0x8001 (EG 1), getter 0x0001 | field | on-change | 6× uint8 raw + status |
| | | SetCentralLock | 0x0010 | method | – | request: uint8 (0 none, 1 lock, 2 unlock) |
| | | OpenTrunk | 0x0011 | fire&forget | – | open: boolean |
| EnergyService | 0x6003 | BatteryStatus | 0x8001 (EG 1), getter 0x0001 | field | on-change (min 100 ms) + 1 s cyclic | SoC, voltage, current |
| ClimateService | 0x6004 | SetCabinClimate | 0x0001 | method | – | setpointDegC: float32, fanLevel: uint8 |

All services: instance 0x0001, interface version 1.0.

## 6. Configuration validation

`validateConfig()` runs in the `S2SGateway` constructor; a broken matrix
throws `ConfigError` listing every problem instead of misbehaving at run time:

- CAN ID range, classic / FD payload length
- signals inside the payload, no overlapping bits (incl. E2E CRC/counter), unique names, factor ≠ 0, min ≤ max
- unique CAN IDs per direction, unique message names
- event IDs with bit 15 set, method/getter IDs with bit 15 clear, no ID reuse within a service instance
- every element / argument references an existing Rx / Tx signal; a Tx signal has a single writer
- cyclic modes have a cycle time; Tx PDUs are actually transmitted; bursts have an interval

## 7. Integration on the HPC

`ccg_s2s_gateway` is a ready-to-run Linux process:

```
ccg_s2s_gateway --can can0 [--fd] --port 30490 --subscriber 10.0.0.20:30501 [--period-ms 5]
```

- `poll()` loop over the SocketCAN and UDP sockets, `mainFunction()` every 5 ms.
- `CAN_RAW_FILTER` with the S2S Rx IDs, CAN FD supported (`--fd`).
- Multiple SOME/IP messages per UDP datagram are handled.
- Static service discovery: every `--subscriber` is subscribed to all eventgroups and receives initial field values at start.

`ccg_s2s_gateway_vsomeip` uses vsomeip instead (`platform/vsomeip/VsomeipServerBinding`,
configuration `config/vsomeip/hpc_s2s_gateway.json`): services are offered with
SOME/IP-SD, subscriptions call `onSubscribe` (initial field values via `notify_one`),
and requests / subscriptions are handed from the vsomeip threads to the gateway
executor through an eventfd. Events are offered with `update_on_change = true` and
notified with `force`, because the gateway does its own timing (vsomeip would
otherwise send only on its own cycle). `ccg_hpc_vsomeip_bench` runs the same with
simulated ECUs instead of SocketCAN. The consumer on the Android IVI is described in
[IVI_ANDROID_VSOMEIP.md](IVI_ANDROID_VSOMEIP.md).

For other stacks the adapters are replaced behind the same interfaces:
`ISomeIpBinding` → ara::com binding, `ICanTransmitter` → CanIf / SocketCAN with a TX queue.

## 8. Limitations / next steps

- SOME/IP-SD, SOME/IP-TP (segmentation > 1400 bytes) and TCP are delegated to the binding
  (static SD in the UDP binding, full SD with vsomeip).
- E2E is Profile-1 style for CAN; SOME/IP-side E2E (Profile 4/7) is not applied.
- Arrays, structs and strings are not used as service element types (flat basic types only).
- The matrix is hand written; in a series project it is generated from DBC/ARXML and FIDL/ARXML.
- No security (SecOC / TLS) – handled by the respective lower layers.
