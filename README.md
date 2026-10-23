# Central Control Gateway – HPC

Gateway functions for a vehicle HPC (high performance computer):

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

Both functions check their configuration at start-up and come with a Linux
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
```

On a Linux HPC / bench PC with (virtual) CAN interfaces:

```sh
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
./build/ccg_s2s_gateway --can vcan0 --port 30490 --subscriber 127.0.0.1:30501

./build/ccg_eth_gateway --bind PT_CAN=can0 --bind CHS_CAN=can1 --bind BODY_CAN=can2 \
    --bind ETH_ADAS=udp:30500:192.168.10.20:30500 --bind ETH_IVI=udp:30501:192.168.10.30:30501
```

## Layout

```
include/ccg/   public headers (can, e2e, someip, s2s, ethgw)
src/           portable core libraries (ccg_s2s, ccg_ethgw)
config/        reference S2S matrix and Ethernet gateway routing table
platform/linux SocketCAN, UDP and SOME/IP-over-UDP bindings
app/           gateway processes and simulators
tests/         unit and integration tests
docs/          design descriptions
```
