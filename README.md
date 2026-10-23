# Central Control Gateway – HPC

Gateway functions for a vehicle HPC (high performance computer): signal-to-service, Ethernet routing with SecOC and key management, and diagnostic routing.

## Signal-to-Service (S2S)

Translates CAN signals into SOME/IP events/fields and SOME/IP method calls into CAN signals.

- DBC-compliant signal codec (Intel/Motorola, signed, factor/offset, SNA, range)
- CAN E2E protection (CRC-8 SAE J1850 + alive counter, debounced error handling)
- Signal status per service element (`VALID`, `INVALID`, `TIMEOUT`, `E2E_ERROR`, `NOT_AVAILABLE`) with substitution values
- On-change (with debounce), cyclic and mixed event transmission; fields with getter and initial event
- Method → CAN with range check, all-or-nothing writes, burst repetitions, minimum delay time, pulse signals
- SOME/IP return codes per specification
- vsomeip binding with SOME/IP-SD (`ccg_s2s_gateway_vsomeip`)

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

DoIP edge node for the external tester, routing UDS requests to the ECUs on CAN and to the DoIP ECUs on the vehicle Ethernet.

- **DoIP (ISO 13400-2)**: vehicle identification and announcements, entity status, power mode (UDP); routing activation with alive-check socket handling, inactivity timers, header NACKs, diagnostic message ACK/NACK (TCP)
- **DoIP over TLS** (ISO 13400-2:2019, port 3496, OpenSSL): TLS 1.2 ECDHE/AES-GCM or TLS 1.3, optional mutual TLS against a tester CA; plain TCP can be refused (activation code 0x07); a verified client certificate unlocks central security activation (0xE0) and the key routines that change keys (otherwise NRC 0x33)
- **Certificate revocation** for both TLS sides with CRLs (`--tls-crl`, `--vehicle-crl`): revoked certificates fail the handshake; missing CRLs are refused (configurable); outdated CRLs are still used and counted for offline vehicles; changed CRL files are reloaded and sessions of newly revoked testers or ECUs are closed; **delta CRLs** (`--tls-delta-crl`, `--vehicle-delta-crl`) are signature-checked, matched to their base CRL number and applied on top (removeFromCRL lifts a hold); obsolete deltas are ignored, deltas for a newer base are refused; **CRL distribution points** (`--tls-crl-fetch`, `--vehicle-crl-fetch`): when online the gateway downloads (HTTP) the CRLs named in the trust file, the peer certificates (only if their signatures verify up to a trust anchor) and Freshest CRL extensions, takes only signed CRLs newer than the ones in force, closes revoked sessions, refreshes at nextUpdate and keeps them in a cache for offline restarts
- **OCSP stapling** (TLS 1.3 and 1.2): the gateway staples the backend-supplied OCSP response for its own certificate (`--tls-ocsp`, reloaded on change, never past nextUpdate) and verifies the ECUs' staples (signer, certificate, validity, status); "revoked" always fails, a missing or bad staple fails with `--vehicle-ocsp-require`; **must-staple** (RFC 7633) is enforced both ways: an ECU certificate demanding it needs a good staple regardless of policy, a must-staple gateway certificate needs its OCSP response to start, and only responses about the server's own certificate are stapled
- **TLS towards the Ethernet ECUs**: the gateway connects to ADAS as TLS client: the ADAS certificate must come from the vehicle CA and carry the route's name (`adas-dc`), the gateway presents its vehicle certificate, there is no plain fallback, and ADAS accepts TLS only
- **ISO-TP (ISO 15765-2)** on CAN and CAN FD: single/first/consecutive/flow-control frames, escape lengths > 4095 bytes, block size and STmin, N_As/N_Bs/N_Cr timeouts, FC.WAIT, overflow
- **Routing** by logical address to the ECU's CAN channel and IDs; functional requests (0xE400) on 0x7DF on every bus; responses including NRC 0x78 *response pending* go back to the requesting tester
- Local UDS server for the gateway's own address (session control, tester present, VIN / serial number), extensible by further services
- **DoIP-to-DoIP routing** to Ethernet ECUs (ADAS 0x1010): the gateway connects to the ECU's DoIP entity with the tester's own source address; ACK after the ECU's ACK, its NACKs passed on (0x06 if unreachable), responses including NRC 0x78 forwarded, functional requests reach the Ethernet ECUs too
- Gateway-internal diagnostic client: own UDS requests to CAN ECUs (ISO-TP) and to Ethernet ECUs as **DoIP client** (TCP connect, routing activation, ACK/NACK, alive check, NRC 0x78)

Design: [docs/DIAG_GATEWAY_DESIGN.md](docs/DIAG_GATEWAY_DESIGN.md)

## SecOC (Secure Onboard Communication)

Authenticity, integrity and replay protection for security-relevant PDUs routed by the Ethernet gateway.

- **AUTOSAR SecOC** secured I-PDUs: authentic PDU + truncated freshness value + truncated AES-128-CMAC over Data ID, PDU and complete freshness value
- **Verification** of received secured PDUs before routing: tampered, forged and replayed PDUs are dropped and reported as security events (IdsM)
- **Re-authentication** with the target domain's key and profile (e.g. Ethernet 64-bit FV/MAC → CAN profile 1 "24Bit-CMAC-8Bit-FV")
- **Freshness value manager**: counter mode (Ethernet) and synchronised trip/reset/message counter mode (CAN), FV reconstruction from truncated values, acceptance window, multiple verify attempts, persistence
- **Freshness value synchronisation master**: the gateway owns trip and reset counter (trip counter persisted at every power-up) and broadcasts authenticated sync messages on every bus; ECUs follow as FV slaves
- Crypto service interface for the HSM, software AES-128-CMAC verified against FIPS-197, RFC 4493 and OpenSSL

Design: [docs/SECOC_DESIGN.md](docs/SECOC_DESIGN.md)

## SecOC key management

Key slots of the gateway HSM and their renewal from the backend.

- **SHE memory update protocol**: keys arrive encrypted and authenticated (M1–M3, authorised by MASTER_ECU_KEY) and are confirmed with M4/M5; verified against the SHE specification example
- **Protection**: anti-rollback update counter per key, UID binding (wildcard only if allowed), write protection, MAC-only key usage, lockout after repeated authentication failures
- **Rollover without communication loss**: new keys are staged until the backend activates them; the previous key is still accepted for verification during a grace period, the pending key already verifies MACs of ECUs that switched early
- **UDS on DoIP** (gateway address 0x1001): RoutineControl F200 load key, F201 activate, F202 discard; DID F2A0 key status; the key store is persisted before M4/M5 are returned
- **In-vehicle key master**: the gateway generates the SecOC keys it shares with VCU, EPS and BCM (CAN) and the ADAS domain controller (Ethernet) and distributes them with the same SHE protocol, over ISO-TP and as DoIP client over TLS (port 3496, routing activation as in-vehicle tester 0x0F00) (ECU authorisation keys derived from the vehicle key master secret and the ECU's UID). Each key group is atomic: it is activated only when every member proved it holds the key, and otherwise discarded everywhere. Started with RoutineControl F210
- Security events for the IdsM; backend tool `ccg_key_tool` builds M1–M3 and checks M4/M5

Design: [docs/KEY_MANAGEMENT_DESIGN.md](docs/KEY_MANAGEMENT_DESIGN.md)

## IVI controller (Android)

COVESA vsomeip 3.7 ported to the Android IVI: the HPC services above become Vehicle HAL properties.

- **vsomeip on Android**: patch (socket base path usable by `early_hal` services, vendor config path, Boost version), Boost 1.83 for `external/boost`, repo local manifest and setup script
- **SOME/IP routing daemon** `ccg_someipd`: vsomeip routing manager that also brings the vehicle interface up, assigns its address and keeps the SOME/IP-SD multicast route Android lacks (without it vsomeip never starts SD)
- **Vehicle HAL**: `IVehicleHardware` backend for the AOSP `DefaultVehicleHal`: speed, steering angle, doors, central lock, trunk, battery, HVAC with status mapping (`VALID` → AVAILABLE, `TIMEOUT` → UNAVAILABLE, `INVALID` / `E2E_ERROR` → ERROR)
- **Portable IVI client** (`ivi/`): typed codec, service availability, request supervision, field refresh by getter; unit tested against the real S2S gateway
- SELinux policy, init scripts, Ethernet overlay, product makefiles
- Two-ECU test in network namespaces (`tools/ivi_hpc_netns_test.sh`)

Design: [docs/IVI_ANDROID_VSOMEIP.md](docs/IVI_ANDROID_VSOMEIP.md)

All functions check their configuration at start-up and come with a Linux
process and a deterministic virtual-time simulator.

## Build & test

```sh
cmake -S . -B build -G Ninja -DCCG_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure    # or ./build/ccg_tests [filter]
```

Requirements: C++17 compiler (GCC ≥ 9 / Clang ≥ 10), CMake ≥ 3.16. Optional: OpenSSL 3 for DoIP over TLS (and a test cross-check of the AES-CMAC); everything else has no third-party dependencies.

Optional vsomeip targets (`ccg_s2s_gateway_vsomeip`, `ccg_hpc_vsomeip_bench`, `ccg_someipd`,
`ccg_ivi_vehicle_client`) are built when vsomeip 3 is found
(`-DCMAKE_PREFIX_PATH=<vsomeip install>`, `-DCCG_WITH_VSOMEIP=ON|OFF|AUTO`).
Two-ECU test of the IVI against the HPC in network namespaces (root):

```sh
sudo tools/ivi_hpc_netns_test.sh build <vsomeip install>/lib
```

## Run

Bench simulations (no hardware, print the traffic the gateway produces):

```sh
./build/ccg_s2s_sim
./build/ccg_eth_gw_sim
./build/ccg_diag_sim
./build/ccg_keym_sim
./build/ccg_key_master_sim
```

On a Linux HPC / bench PC with (virtual) CAN interfaces:

```sh
sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
./build/ccg_s2s_gateway --can vcan0 --port 30490 --subscriber 127.0.0.1:30501

./build/ccg_eth_gateway --bind PT_CAN=can0 --bind CHS_CAN=can1 --bind BODY_CAN=can2 \
    --bind ETH_ADAS=udp:30500:192.168.10.20:30500 --bind ETH_IVI=udp:30501:192.168.10.30:30501 \
    --key-store keys.dat --fv-store freshness.dat   # or --keys FILE / --demo-keys

./build/ccg_diag_gateway --can PT_CAN=can0 --can CHS_CAN=can1 --can BODY_CAN=can2 \
    --key-store keys.dat --demo-keys \
    --tls-cert gw.pem --tls-key gw.key --tls-ca testers.pem \
    --vehicle-ca vehicle-ca.pem --vehicle-cert gw-vehicle.pem --vehicle-key gw-vehicle.key \
    --tls-crl testers.crl --vehicle-crl vehicle.crl --tls-delta-crl testers-delta.crl --tls-ocsp gw.ocsp \
    --tls-crl-fetch testers-cache.crl --vehicle-crl-fetch vehicle-cache.crl
    # testers: DoIP 13400 + TLS 3496; ADAS over TLS; revocation; key routines, key master

./build/ccg_key_tool --uid 000000000000004343470000000001 --slot 6 --auth-slot 1 \
    --auth-key <MASTER_ECU_KEY> --key <new key> --counter 2      # backend: M1..M3, expected M4/M5
```

With vsomeip and SOME/IP-SD instead of static subscribers:

```sh
VSOMEIP_CONFIGURATION=config/vsomeip/hpc_s2s_gateway.json ./build/ccg_s2s_gateway_vsomeip --can vcan0
```

Android IVI: see [docs/IVI_ANDROID_VSOMEIP.md](docs/IVI_ANDROID_VSOMEIP.md) §4 (AOSP integration).

## Layout

```
include/ccg/      public headers (can, e2e, someip, s2s, ethgw, isotp, doip, diag, crypto, secoc, keym)
src/              portable core libraries (ccg_s2s, ccg_ethgw, ccg_diag, ccg_secoc, ccg_keym)
config/           reference S2S matrix, Ethernet routing table, diagnostic routing table, key slots,
                  vsomeip configurations (HPC, IVI)
ivi/              IVI client of the HPC services and VHAL property mapping (ccg_ivi)
platform/linux    SocketCAN, UDP, SOME/IP-over-UDP and DoIP sockets, SecOC key file / key store /
                  freshness store, vehicle network setup (netlink)
platform/vsomeip  vsomeip bindings: HPC server binding, IVI client transport
sim/              simulated UDS ECU for tests and the diagnostic simulator
app/              gateway processes, simulators, HPC vsomeip bench, IVI routing daemon and client
android/          AOSP integration: vsomeip patch, Boost, VHAL, init, SELinux, product
Android.bp        Soong modules of the IVI side
tests/            unit and integration tests
tools/            two-ECU integration test (network namespaces)
docs/             design descriptions
```
