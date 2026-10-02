# Central Control Gateway – HPC S2S

Signal-to-Service (S2S) gateway function for a vehicle HPC: translates CAN
signals into SOME/IP events/fields and SOME/IP method calls into CAN signals.

- DBC-compliant signal codec (Intel/Motorola, signed, factor/offset, SNA, range)
- CAN E2E protection (CRC-8 SAE J1850 + alive counter, debounced error handling)
- Signal status per service element (`VALID`, `INVALID`, `TIMEOUT`, `E2E_ERROR`, `NOT_AVAILABLE`) with substitution values
- On-change (with debounce), cyclic and mixed event transmission; fields with getter and initial event
- Method → CAN with range check, all-or-nothing writes, burst repetitions, minimum delay time, pulse signals
- SOME/IP return codes per specification
- Configuration consistency check at start-up
- Linux process (SocketCAN + SOME/IP/UDP) and deterministic virtual-time simulator

See [docs/S2S_DESIGN.md](docs/S2S_DESIGN.md) for the design and the reference matrix.

## Build & test

```sh
cmake -S . -B build -G Ninja -DCCG_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure    # or ./build/ccg_s2s_tests [filter]
```

Requirements: C++17 compiler (GCC ≥ 9 / Clang ≥ 10), CMake ≥ 3.16. No third-party dependencies.

## Run

Bench simulation (no hardware, prints the SOME/IP and CAN traffic):

```sh
./build/ccg_s2s_sim
```

On a Linux HPC / bench PC with a (virtual) CAN interface:

```sh
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
./build/ccg_s2s_gateway --can vcan0 --port 30490 --subscriber 127.0.0.1:30501
```

## Layout

```
include/ccg/   public headers (can, e2e, someip, s2s)
src/           portable S2S core library (ccg_s2s)
config/        reference vehicle S2S matrix
platform/linux SocketCAN and SOME/IP-over-UDP bindings
app/           gateway process and simulator
tests/         unit and integration tests
docs/          design description
```
