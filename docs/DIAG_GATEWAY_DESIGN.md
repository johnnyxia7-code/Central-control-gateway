# HPC Diagnostic Gateway – DoIP to UDS on CAN

## 1. Purpose

The external tester (workshop tester, end-of-line station, flashing tool) talks
**DoIP** (ISO 13400-2) to the HPC over Ethernet. Most ECUs still sit on CAN and
speak **UDS** (ISO 14229) over **ISO-TP** (ISO 15765-2). The diagnostic gateway
on the HPC is the DoIP edge node: it terminates DoIP and forwards the UDS
messages to the right ECU on the right CAN bus, then sends the answers back.

```
 Tester ──TCP/UDP 13400── HPC diagnostic gateway ──ISO-TP── PT_CAN  (CAN FD): VCU 0x0010, BMS 0x0011
  SA 0x0E80               LA 0x1001                         CHS_CAN (CAN)   : ESP 0x0020, EPS 0x0021
                          functional 0xE400                 BODY_CAN (CAN)  : BCM 0x0030
```

## 2. Layers

| Layer | Module | Content |
|-------|--------|---------|
| DoIP message | `ccg/doip/doip_message.hpp` | generic header (version, inverse version, payload type, length), payload types, NACK/response codes, TCP stream reassembly, payload builders |
| ISO-TP | `ccg/isotp/isotp_channel.hpp` | SF/FF/CF/FC on CAN and CAN FD, flow control, timers |
| Routing | `ccg/diag/diag_gateway.hpp` | DoIP entity (UDP + TCP), routing activation, address-based routing to ISO-TP channels, local UDS server |
| Platform | `platform/linux/doip_sockets.hpp` | TCP listener (max + 1 sockets), UDP socket with broadcast |

## 3. DoIP entity

### 3.1 UDP (port 13400)

| Request | Answer |
|---------|--------|
| Vehicle identification 0x0001 (version 0xFF allowed) | Vehicle announcement 0x0004: VIN, LA, EID, GID, further action 0x00, sync status 0x00 |
| … with EID 0x0002 / with VIN 0x0003 | same, only if EID / VIN match; otherwise no answer |
| Entity status 0x4001 | 0x4002: node type gateway, max sockets, open sockets, max data size |
| Power mode 0x4003 | 0x4004: ready (0x01) |
| bad pattern / wrong length / unknown type | generic NACK 0x00 / 0x04 / 0x01 |

At start-up the vehicle announcement is broadcast **3 times, 500 ms apart**
(A_DoIP_Announce_Num / Interval).

### 3.2 TCP data sockets

- **Stream framing:** DoIP messages are reassembled from the TCP byte stream,
  so a message may arrive in pieces or several may share one segment.
- **Header errors:**

  | Problem | Reaction |
  |---------|----------|
  | Inconsistent or unsupported version | NACK 0x00, socket closed |
  | Unknown payload type | NACK 0x01, socket stays open |
  | Payload above the limit | NACK 0x02; the payload is skipped and the stream stays in sync |
  | Wrong length for the payload type | NACK 0x04, socket closed |

- **Inactivity:** a socket without routing activation is closed after 2 s
  (T_TCP_Initial_Inactivity), an active one after 5 min without traffic
  (T_TCP_General_Inactivity).

### 3.3 Routing activation (0x0005 → 0x0006)

| Situation | Response code |
|-----------|---------------|
| SA outside the tester range 0x0E00..0x0FFF | 0x00 unknown SA, socket closed |
| Activation type other than default (0x00) / WWH-OBD (0x01) | 0x06 unsupported, socket closed |
| Socket already active with another SA | 0x02 SA mismatch, socket closed |
| SA active on **another** socket | alive check (0x0007) on that socket: it answers → 0x03 SA in use; silent for 500 ms → old socket closed, **0x10** |
| All `maxTcpConnections` sockets active | alive check on all of them: all answer → 0x01 no free socket; one silent → it is closed, **0x10** |
| Otherwise | **0x10 success** |

The TCP listener accepts `maxTcpConnections + 1` sockets, so a surplus tester
can still receive its 0x01 rejection. One activation handshake runs at a time.

### 3.4 Diagnostic messages (0x8001)

Payload: `SA (2) | TA (2) | UDS data`.

| Check | Reaction |
|-------|----------|
| Socket not activated, or SA ≠ activated SA | NACK 0x02 invalid SA, socket closed |
| TA = gateway LA 0x1001 | ACK, local UDS server answers (§5) |
| TA = functional 0xE400 | ACK from 0xE400, single frame on 0x7DF on **every** CAN bus (§4.3) |
| TA = ECU LA | ISO-TP to the ECU; ACK **after** ISO-TP delivered the request, NACK 0x08 on ISO-TP failure |
| Request longer than the ECU's `maxRequestLength` | NACK 0x04 too large |
| ECU's ISO-TP channel still sending the previous request | NACK 0x08 |
| Unknown TA | NACK 0x03 |

ACK/NACK carry `SA = target of the request`, `TA = tester`. Responses from the
ECU are sent as diagnostic messages `SA = ECU`, `TA = tester` to the tester
that last addressed this ECU. This includes several responses per request,
e.g. NRC 0x78 *response pending* followed by the final answer. If that tester
has disconnected, the response is dropped (`responsesDropped`).

## 4. ISO-TP (ISO 15765-2)

### 4.1 Frames (normal addressing)

| Frame | PCI | Notes |
|-------|-----|-------|
| SF | `0L` | 1..7 bytes |
| SF (CAN FD) | `00 LL` | 8..62 bytes |
| FF | `1H LL` | 12-bit length, 8..4095 |
| FF (escape) | `10 00 LLLLLLLL` | 32-bit length > 4095 (ISO 15765-2:2016) |
| CF | `2N` | SN 1..15, 0, 1 … |
| FC | `3S BS STmin` | S: 0 continue, 1 wait, 2 overflow |

Frames are padded with 0xCC to 8 bytes (classic CAN) or to the next valid
CAN FD length (12, 16, 20, 24, 32, 48, 64).

### 4.2 Flow control and timing

- **Sender:** obeys the receiver's block size and STmin. STmin 0xF1..0xF9
  (100–900 µs) is rounded up to 1 ms and reserved values are treated as
  127 ms. With STmin 0 up to 64 CFs go out back-to-back, then the sender
  yields until the next 1 ms tick.
- **Timers and limits:**

  | Timer / limit | Value | On expiry |
  |---------------|-------|-----------|
  | N_As | 1 s | a frame the controller keeps refusing → abort |
  | N_Bs | 1 s | no flow control from the receiver → abort |
  | N_Cr | 1 s | no consecutive frame from the sender → abort |
  | maxWft | 10 | more FC.WAIT frames → abort |

- **Receiver:**
  - Sends an FC after the FF and after every block.
  - Answers FC.OVFLW when the message is larger than `maxRxLength`.
  - Aborts on a wrong sequence number, or when a new SF/FF arrives in the middle of a reception.

### 4.3 Functional requests

Functional requests are single frames by definition. The gateway sends them as
classic CAN frames on ID 0x7DF on every channel, including the CAN FD bus. A
request that does not fit a classic single frame (> 7 bytes) gets NACK 0x04.
Every ECU may answer on its own physical response ID. All answers are routed to
the requesting tester, and the gateway's own answer is added too.

## 5. Local UDS server (LA 0x1001)

| Service | Behaviour |
|---------|-----------|
| 0x10 DiagnosticSessionControl 01/03 | `50 xx 00 32 01 F4` (P2 50 ms, P2* 5 s), suppress bit honoured |
| 0x3E TesterPresent 00 | `7E 00`, suppress bit honoured |
| 0x22 ReadDataByIdentifier | F190 VIN, F186 active session, F18C serial number; NRC 0x31 otherwise |
| 0x31 RoutineControl F200/F201/F202, 0x22 F2A0 | SecOC key management (with `--key-store`), see [KEY_MANAGEMENT_DESIGN.md](KEY_MANAGEMENT_DESIGN.md) |
| others | NRC 0x11 |

Further services plug in as `diag::ILocalServiceHandler` (`DiagGateway::addLocalService`);
handlers are asked before the built-in services.

On functional requests, NRCs 0x11/0x12/0x31/0x7E/0x7F are suppressed (ISO 14229-1).
The session falls back to the default session after S3 = 5 s without a request.

## 6. Reference routing table (`config/vehicle_diag_routing.cpp`)

| ECU | LA | Channel | Request / response ID | ISO-TP | Max request |
|-----|----|---------|----------------------|--------|-------------|
| VCU | 0x0010 | PT_CAN | 0x7E0 / 0x7E8 | CAN FD (TX_DL 64) | 8192 B |
| BMS | 0x0011 | PT_CAN | 0x7E1 / 0x7E9 | classic | 4095 B |
| ESP | 0x0020 | CHS_CAN | 0x720 / 0x728 | classic | 4095 B |
| EPS | 0x0021 | CHS_CAN | 0x721 / 0x729 | classic | 4095 B |
| BCM | 0x0030 | BODY_CAN | 0x740 / 0x748 | classic | 4095 B |

Entity: VIN `WCCG0HPC0RT000001`, LA 0x1001, functional 0xE400, testers
0x0E00..0x0FFF, 2 TCP sockets, 8192 B max diagnostic message, protocol
version 0x02 (ISO 13400-2:2012).

`validateDiagConfig()` rejects:
- a VIN that is not 17 characters;
- duplicate logical addresses, or ECU addresses in the tester range;
- addresses that collide with the gateway or functional address;
- CAN ID clashes per channel, including the functional ID;
- CAN FD ISO-TP on a classic channel;
- unknown channels;
- `maxRequestLength` above the DoIP limit.

## 7. Integration

```
ccg_diag_gateway --can PT_CAN=can0 --can CHS_CAN=can1 --can BODY_CAN=can2 \
                 [--port 13400] [--broadcast 255.255.255.255]
```

- **Process loop:** one `poll()` loop over the TCP listener, the TCP data
  sockets, the UDP socket and the CAN sockets; `mainFunction()` runs every 1 ms.
- **CAN filters:** the kernel filters only pass the ECUs' response IDs.
- **Simulation:** `ccg_diag_sim` replays a scripted tester session against
  simulated UDS ECUs (`sim/uds_ecu.*`) in virtual time.

## 8. Limitations / next steps

- No TLS (ISO 13400-2:2019 port 3496) and no authentication / confirmation in
  routing activation (codes 0x04, 0x05, 0x11 are never sent).
- One outstanding physical request per ECU; a second one is refused with NACK
  0x08 rather than queued.
- No DoIP routing to other Ethernet ECUs (DoIP-to-DoIP), only to CAN.
- No extended or mixed ISO-TP addressing, and no LIN diagnostics.
- The UDS server of the gateway itself is minimal (session, tester present, three DIDs).
