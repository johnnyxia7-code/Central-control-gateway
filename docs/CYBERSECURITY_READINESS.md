# IDPS and SecOC deployment readiness

Assessment date: 2026-10-26 UTC. Scope: the C++17 gateway libraries, reference
configuration, Linux adapters and applications, simulators, tests and CI in PR #1.
Baseline requested: ISO/SAE 21434 and UN Regulation No. 155 alignment.

**Decision: suitable for further controlled integration testing; production
vehicle release is not approved by this review.** The implementation provides
useful security controls and regression evidence. It does not provide a complete
vehicle cybersecurity management system, a vehicle-specific TARA, a production
HSM backend, or a complete AUTOSAR IdsM/IdsR integration. No target ECU, production
network, OEM cybersecurity requirements, licensed standard text, or certification
evidence was supplied. No vehicle deployment was performed.

## Basis and limits

ISO/SAE 21434 covers cybersecurity risk management across the vehicle E/E
lifecycle; it does not prescribe a particular technology. Implementing SecOC and
an event recorder therefore contributes implementation evidence, but cannot by
itself establish lifecycle conformity. This is an engineering gap assessment,
not a clause-by-clause audit of the licensed standard.
[ISO/SAE 21434:2021 official overview](https://www.iso.org/standard/70918.html).

R155 alignment needs evidence at the manufacturer/vehicle level for risk
assessment, mitigation, monitoring, detection, response and forensic analysis.
The release owner must establish the applicable regulation series and market
requirements. This repository review does not establish type approval or CSMS
certification. [UNECE R155 publication](https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155-cyber-security-and-cyber-security),
[UNECE-hosted regulatory overview](https://unece.org/sites/default/files/2023-09/WP5_Session36_KaiFrederikZastrow.pdf).

AUTOSAR SecOC and IdsM R24-11 were used as architectural references. SecOC covers
authenticity and freshness. The IdsM reference includes asynchronous buffering,
qualification/filtering, bounded event storage and reporting. The local recorder
below implements a limited reference path, without claiming AUTOSAR API, wire
format, qualification-filter or platform conformance.
[SecOC specification](https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_SecureOnboardCommunication.pdf),
[IdsM specification](https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_IntrusionDetectionSystemManager.pdf).

## Findings corrected in this review

| ID | Problem and resulting behavior | Implementation and evidence |
|---|---|---|
| SEC-01 | Discarding a pending key previously forgot its generation, permitting the same SHE container to be accepted again. Each slot now retains its highest accepted counter through discard, snapshot and restart. | `key_manager.cpp`; tests `discarded update counters survive restart` and `discarded counter floor persists`. |
| SEC-02 | A campaign previously inferred the next generation only from active/pending keys. DID F2A2 now exposes retained counters; the key master requires it and chooses a larger generation. Response SID/DID/routine echoes, duplicate entries, counter ranges and activation counts are checked. | `key_master.cpp`, `key_management_service.cpp`; campaign regression for a discarded generation 41 advancing to 42. |
| SEC-03 | A failed key-store write could leave a new key active in memory while execution continued. A persistence callback now commits proposed state before provisioning, staging, activation, discard or expiry becomes visible. The Linux diagnostic process exits on a failed durable commit. | `KeyManager::commit`, `diag_gateway_main.cpp`; injected failures check unchanged keys and no successful key events. |
| SEC-04 | Snapshot restoration modified live keys before validation; malformed or rolled-back reloads could partly replace them. Restoration now validates a temporary state, rejects duplicates, unknown slots and inconsistent generations, then replaces the state. Failed Linux reload stops processing. | `KeyManager::restore`; invalid-snapshot regression. |
| SEC-05 | The key-store parser accepted malformed suffixes, duplicate records and incomplete files. New stores have a version and terminal marker, strict unsigned numbers, bounded file size and retained counters. Key/freshness writes use exclusive random temporary names, mode 0600, file sync, rename and directory sync. | `key_store.cpp`, `atomic_file.hpp`; parser, persisted-counter and pre-created-temp-link regressions. |
| SEC-06 | Direct SecOC calls could use invalid MAC/freshness widths or read a truncated authenticator. The network path now calls the length-aware verifier; runtime checks reject invalid parameters before bit reads or shifts. Layout changes and freshness regression are rejected. | `secoc.cpp`, `fv_sync.cpp`, `ethernet_gateway.cpp`; truncation, null, invalid-width and epoch regression tests. |
| SEC-07 | The latest-64-event deques did not provide a retained, overload-aware reporting path. The new recorder aggregates events, counts overflow, retries sink failures, and exports through a bounded Linux journal. | `event_recorder.hpp`, `security_journal.hpp`, `security_runtime.hpp`; aggregation, overflow, sink failure, rotation, permissions, reopen and integration tests. |

The eight findings corrected in the preceding PR commit remain covered: forwarded
key-control authorization, TX/RX freshness durability, permissive CRL handshake
state, strict expired delta-CRL handling, diagnostic exchange ownership and
response correlation, uncertain key-load cleanup, and numeric conversion bounds.
The earlier PR Linux Debug and Release CI runs both passed before this review.

## Reference IDPS path

Sensors report numeric event IDs and configured source identifiers; no raw packets,
keys, UIDs, certificate contents or request payloads are included in journal records.

| Event ID | Meaning | Source |
|---|---|---|
| 0 | Overflow count for event/source pairs that could not be queued | 0 |
| 1 | SecOC MAC or crypto verification failure | Configured PDU index |
| 2 | SecOC freshness failure | Configured PDU index |
| 3 | PDU length/input failure | Configured PDU index |
| 4 | Malformed Ethernet PDU datagram | Configured channel index |
| 5 | SecOC transmit protection failure | Configured PDU index |
| 6 | Rejected unauthenticated F201/F202/F210 key control | Diagnostic target address |
| 7 | Process event-sink initialization | 0 |
| 100..107 | Provisioned, loaded, staged, rejected, locked, activated, discarded, previous-key expired | SHE slot |

The single-executor recorder holds at most 64 distinct event/source pairs. Repeated
events aggregate into a saturating count with first/last monotonic timestamps.
Each flush attempts at most 16 records, no more often than once per second. A
failed sink retains the record and increments a health counter; full-queue losses
are counted and reported as event 0. These values are reference resource bounds,
not OEM detection thresholds or requirements derived from a TARA.

Both Linux gateways accept `--security-log FILE`. Use **different paths for each
process**, in a pre-created private directory owned by the service identity.
Each writer retains the current file plus `.1`, each at most 1 MiB. Files are
0600, regular files, single-link and owner checked; symlinks, public files and
torn trailing records are rejected. Requested sink initialization failure stops
startup. Runtime failures produce health errors and bounded retries. A torn
journal needs explicit preservation/recovery by operations before restarting.

Example additions to the existing, site-specific launch commands:

```text
ccg_eth_gateway ... --key-store /var/lib/ccg/keys --fv-store /var/lib/ccg/freshness --security-log /var/lib/ccg/eth-security.jsonl
ccg_diag_gateway ... --key-store /var/lib/ccg/keys --security-log /var/lib/ccg/diag-security.jsonl
```

Without `--security-log`, records go to stderr and startup prints a retention
warning. The journal writes synchronously; it is a bench adapter, not a real-time
production storage service. Runtime storage failure does not automatically stop
driving traffic. Qualified vehicle containment behavior must be designed with
safety engineering. Successful or uncertain writes may be repeated; a collector
must identify a writer by session/PID and deduplicate event sequence IDs, retaining
the highest aggregate count. Sequences describe event creation, not file order.
The queue is volatile: a crash before a successful flush can lose its contents.
Rotation intentionally overwrites old evidence, so offboard retention is required.

## Key-store and ECU protocol migration

1. Quiesce key campaigns and stop both gateway processes; preserve the existing
   store with restricted access. Deploy matching gateway and ECU software.
2. Every participating ECU must implement `22 F2 A2` -> `62 F2 A2 <count>` followed
   by `<slot:u8><highestAcceptedCounter:u32 big endian>`. Existing F2A0 and F2A1
   retain their layouts. Missing, malformed or inconsistent F2A2 replies refuse
   renewal; there is no fallback that guesses discarded counters.
3. The loader accepts old key files for controlled migration and infers counters
   from available keys. An old file cannot recover the generations of keys
   discarded before this fix. Recover the maximum from the provisioning/campaign
   authority, or reprovision under an approved procedure before accepting updates.
   Do not simply reuse the next active-key counter.
4. New files contain `version 2`, per-slot `counter` records, key-state records,
   and `end`. Older software must not consume this format. Do not downgrade by
   deleting counter records. Validate a saved/restored snapshot on the bench
   before resuming traffic and renewal.
5. Install `KeyManager::setPersistence` before enabling updates in every target
   adapter. Its callback must durably save the complete proposed snapshot or
   throw; propagate that failure to a controlled stop. The legacy UDS-level
   `bool()` persistence callback is retained for bench compatibility and is not
   an atomic commit guarantee.

After all load proofs succeed, the existing campaign policy switches the gateway
even if an ECU activation acknowledgement is lost or invalid, while returning
`ActivationFailed`. This supports convergence with ECUs that may already have
switched; it is not atomic rollback of a distributed campaign. Release gate G04
requires an approved recovery policy and evidence for this state.

## Production release gates still open

| Gate | Evidence required to close it | Suggested accountable function |
|---|---|---|
| G01: cybersecurity requirements and TARA | Vehicle item definition, assets/trust boundaries, attack paths, risk decisions and traceability to explicit requirements; peer review of residual risk. | OEM cybersecurity lead |
| G02: keys and state protection | HSM/Csm integration, unique provisioning, entropy assurance, access control, debug lock and rollback-resistant NvM. Plaintext software keys and filesystem counters are insufficient against a privileged attacker or restored disk image. | ECU platform/security |
| G03: ECU-only restart freshness | Prove safe resynchronization after a transmitting or receiving slave resets while the master stays running. `FreshnessManager::Snapshot` does not persist the slave's current trip/reset and synchronized TX counter. An old authenticated sync or reuse of a message counter after ECU reset remains a deployment risk. Require an approved anti-replay bootstrap, persistent reservation or equivalent design. | Network/security architecture |
| G04: key lifecycle recovery | Crash/power-loss testing during each multi-ECU phase, restart-safe campaign recovery, persistent anti-rollback counters including discarded keys, and trusted grace-period expiry across downtime. Campaign results are volatile and stored remaining grace time is not a trusted wall-clock expiry. | Key infrastructure owner |
| G05: diagnostic privileges | Roles/permissions per certificate, ECU/service authorization, identity propagation to downstream ECUs, secure local admin and test-mode controls. A valid certificate currently establishes a binary authenticated state; a DoIP source address alone is not tester identity. | Diagnostic security owner |
| G06: transport and network isolation | Approved firewall/VLAN/ACL rules, secure management channel, strict TLS/mTLS, CA lifecycle and explicit offline CRL/OCSP policy. Require `--tls-only`, `--tls-require-client-cert`, and policy-approved strict revocation settings; prohibit `--doip-plain` and demo keys in released configurations. Unsecured configured CAN/SOME-IP routes also need risk treatment. | Vehicle network/PKI |
| G07: event qualification and SOC | OEM event catalogue and severity mapping; rate/threshold/state filters; TLS/OS/network sensors; trusted time; authenticated tamper-evident evidence; persistent retry/offboard export; retention/privacy policy; SOC correlation and response exercises. The new journal is neither authenticated nor rollback protected. | Detection/SOC owner |
| G08: overload and real-time behavior | Sustained CAN/UDP/DoIP/TLS flood testing, per-client receive/accept/CPU budgets, timer latency and memory limits, write latency and flash endurance. Existing socket drain loops and synchronous storage do not establish bounded end-to-end execution time. | Platform/performance |
| G09: prevention and safe response | Vehicle-specific isolation/limp-home/escalation rules, safety analysis of denial or rate limiting, and tests of false positives and legitimate recovery. Authentication failures are dropped; broad autonomous containment is not implemented. | Safety and security leads |
| G10: secure boot/update/supply chain | Signed boot/update chains, anti-rollback release policy, SBOM and dependency vulnerability monitoring, reproducible release build and reviewed configuration provenance. These controls are not established by this repository. | Release/platform owner |
| G11: target validation | HIL/vehicle runs, fuzzing and penetration testing, sleep/wake and battery-disconnect tests, latency/load measurements, long-duration counter/key rollover and actual ECU/TLS interoperability. Loopback and simulation cannot replace these. | Independent validation |
| G12: lifecycle/approval evidence | CSMS processes, incident response and vulnerability handling, supplier responsibilities, post-production monitoring, evidence retention and applicable-market type-approval assessment. | OEM compliance/operations |

Defaults such as 24-bit CAN MACs, 8-bit transmitted freshness, ten-minute key
grace, 3-attempt lockout and permissive offline CRLs are reference choices.
Reassess them against attack feasibility, bus rates, availability and safety.
Do not label a build “ISO/SAE 21434 compliant” or “R155 approved” based on these tests.

## Validation and reproduction

The PR workflow builds all targets and executes the complete suite on Ubuntu
24.04 with OpenSSL required, in Debug, Release and ASan/UBSan configurations.
It includes real loopback TLS/CRL/OCSP, storage and journal tests. The portable
suite also runs locally with warnings as errors and undefined-behavior checks.
The final CI links and counts are recorded in the PR review update.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCCG_WARNINGS_AS_ERRORS=ON -DCMAKE_REQUIRE_FIND_PACKAGE_OpenSSL=ON
cmake --build build --parallel 2
ctest --test-dir build --verbose --output-on-failure
```

Review boundaries: static inspection and deterministic regressions; no production
secrets, vehicle network, hardware HSM, ECU reflashing or live deployment was used.
