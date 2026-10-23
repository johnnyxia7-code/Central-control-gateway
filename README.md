# Central Control Gateway – HPC

Gateway functions for a vehicle HPC (high performance computer): signal-to-service, Ethernet routing with SecOC, and diagnostic routing.

## Signal-to-Service (S2S)

Translates CAN signals into SOME/IP events/fields and SOME/IP method calls into CAN signals.

- DBC-compliant signal codec (Intel/Motorola, signed, factor/offset, SNA, range)
- CAN E2E protection (CRC-8 SAE J1850 + alive counter, debounced error handling)
- Signal status per service element (`VALID`, `INVALID`, `TIMEOUT`, `E2E_ERROR`, `NOT_AVAILABLE`) with substitution values
- On-change (with debounce), cyclic and mixed event transmission; fields with getter and initial event
- Method → CAN with range check, all-or-nothing writes, burst repetitions, minimum delay time, pulse signals
- SOME/IP return codes per specification

Design: [docs/S2S_DESIGN.md](docs/S2S_DESIGN.md)

## Central Ethernet gateway

Routes messages and signals between CAN, CAN FD and Ethernet channels.

- **Message routing** CAN↔CAN, CAN↔Ethernet, Ethernet↔Ethernet with fan-out, ID translation and padding; E2E passes through unchanged
- **Signal routing** with raw copy or rescaling, SNA propagation, and substitution values on Rx timeout or E2E fault
- **Frame decomposition**: one source frame feeds several target frames; received UDP datagrams are split into their PDUs (AUTOSAR SoAd PDU header)
- **Frame assembly**: target frames built from signals of several buses (on update, on change, cyclic, mixed; minimum delay time; E2E protection); several PDUs collected into one UDP datagram (collection timeout, size limit, urgent PDUs)
- Routing table validation: loops, multiple writers, bus length limits, signal overlaps

Design: [docs/ETH_GATEWAY_DESIGN.md](docs/ETH_GATEWAY_DESIGN.md)

## Diagnostic gateway (DoIP → UDS on CAN)

DoIP edge node for the external tester, routing UDS requests to the ECUs on CAN.

- **DoIP (ISO 13400-2)**: vehicle identification and announcements, entity status, power mode (UDP); routing activation with alive-check socket handling, inactivity timers, header NACKs, diagnostic message ACK/NACK (TCP)
- **ISO-TP (ISO 15765-2)** on CAN and CAN FD: single/first/consecutive/flow-control frames, escape lengths > 4095 bytes, block size and STmin, N_As/N_Bs/N_Cr timeouts, FC.WAIT, overflow
- **Routing** by logical address to the ECU's CAN channel and IDs; functional requests (0xE400) on 0x7DF on every bus; responses including NRC 0x78 *response pending* go back to the requesting tester
- Local UDS server for the gateway's own address (session control, tester present, VIN / serial number)

Design: [docs/DIAG_GATEWAY_DESIGN.md](docs/DIAG_GATEWAY_DESIGN.md)

## SecOC (Secure Onboard Communication)

Authenticity, integrity and replay protection for security-relevant PDUs routed by the Ethernet gateway.

- **AUTOSAR SecOC** secured I-PDUs: authentic PDU + truncated freshness value + truncated AES-128-CMAC over Data ID, PDU and complete freshness value
- **Verification** of received secured PDUs before routing: tampered, forged and replayed PDUs are dropped and reported as security events (IdsM)
- **Re-authentication** with the target domain's key and profile (e.g. Ethernet 64-bit FV/MAC → CAN profile 1 "24Bit-CMAC-8Bit-FV")
- **Freshness value manager** with FV reconstruction from truncated values, acceptance window, multiple verify attempts, persistence with restart margin
- Crypto service interface for the HSM, software AES-128-CMAC verified against FIPS-197, RFC 4493 and OpenSSL

Design: [docs/SECOC_DESIGN.md](docs/SECOC_DESIGN.md)

All functions check their configuration at start-up and come with a Linux
process and a deterministic virtual-time simulator.

## Build & test

```sh
cmake -S . -B build -G Ninja -DCCG_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure    # or ./build/ccg_tests [filter]
```

Requirements: C++17 compiler (GCC ≥ 9 / Clang ≥ 10), CMake ≥ 3.16. No third-party dependencies.

## Run

Bench simulations (no hardware, print the traffic the gateway produces):

```sh
./build/ccg_s2s_sim
./build/ccg_eth_gw_sim
./build/ccg_diag_sim
```

On a Linux HPC / bench PC with (virtual) CAN interfaces:

```sh
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
./build/ccg_s2s_gateway --can vcan0 --port 30490 --subscriber 127.0.0.1:30501

./build/ccg_eth_gateway --bind PT_CAN=can0 --bind CHS_CAN=can1 --bind BODY_CAN=can2 \
    --bind ETH_ADAS=udp:30500:192.168.10.20:30500 --bind ETH_IVI=udp:30501:192.168.10.30:30501 \
    --keys secoc.keys --fv-store freshness.dat      # or --demo-keys on the bench

./build/ccg_diag_gateway --can PT_CAN=can0 --can CHS_CAN=can1 --can BODY_CAN=can2   # DoIP on TCP/UDP 13400
```

## Layout

```
include/ccg/   public headers (can, e2e, someip, s2s, ethgw, isotp, doip, diag, crypto, secoc)
src/           portable core libraries (ccg_s2s, ccg_ethgw, ccg_diag, ccg_secoc)
config/        reference S2S matrix, Ethernet routing table, diagnostic routing table
platform/linux SocketCAN, UDP, SOME/IP-over-UDP and DoIP sockets, SecOC key file / freshness store
sim/           simulated UDS ECU for tests and the diagnostic simulator
app/           gateway processes and simulators
tests/         unit and integration tests
docs/          design descriptions
```
