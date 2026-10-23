# IVI Controller – vsomeip on Android

## 1. Purpose

The IVI controller runs Android (Android Automotive OS). It consumes the
SOME/IP services the HPC S2S gateway offers (see [S2S_DESIGN.md](S2S_DESIGN.md))
and makes them available to Android as Vehicle HAL (VHAL) properties, so that
CarService, system UI and apps see vehicle speed, doors, central lock, battery
and climate without knowing about SOME/IP.

The SOME/IP stack on the IVI is [COVESA vsomeip](https://github.com/COVESA/vsomeip)
3.7.6. This document describes what porting it to Android takes, how it is
integrated into the AOSP tree of the IVI, and how it was verified.

```
 IVI controller (Android)                                    HPC (Linux)
┌─────────────────────────────────────────────────────┐     ┌─────────────────────────────┐
│  apps / CarService                                  │     │  S2S gateway (src/s2s)      │
│        │ android.hardware.automotive.vehicle (AIDL) │     │        │                    │
│ ┌──────▼──────────────────────────────────────────┐ │     │  VsomeipServerBinding       │
│ │ vendor.vehicle-hal-ccg                          │ │     │  (platform/vsomeip)         │
│ │  DefaultVehicleHal (AOSP)                       │ │     │        │ vsomeip, routing   │
│ │  SomeIpVehicleHardware  (android/vhal)          │ │     └────────┼────────────────────┘
│ │  VehiclePropertyBridge  (ivi/)  property mapping│ │              │
│ │  VehicleClient          (ivi/)  proxy           │ │              │
│ │  VsomeipClientTransport (platform/vsomeip)      │ │              │
│ └──────┬──────────────────────────────────────────┘ │              │
│        │ UNIX sockets in /dev/socket/someip         │              │
│ ┌──────▼──────────────────────────────────────────┐ │   SOME/IP + SOME/IP-SD
│ │ vendor.ccg.someipd: vsomeip routing manager     │◄├──────────────┘
│ │  + vehicle network setup (link, address, route) │ │   vehicle Ethernet, eth1 192.168.10.30
│ └─────────────────────────────────────────────────┘ │   SD 224.244.224.245:30490
└─────────────────────────────────────────────────────┘   services 192.168.10.1:30510
```

## 2. What the port consists of

vsomeip upstream already compiles for Android (it ships an `Android.bp` and an
Android variant of its `internal.hpp`), but that is far from a working IVI
integration. The gaps found and how they are closed:

| # | Gap on Android | Resolution | Where |
|---|----------------|------------|-------|
| 1 | vsomeip links `libboost_system` / `libboost_filesystem`; AOSP has no Boost | Boost 1.83 package for `external/boost` (headers + System/Filesystem built by Soong; the b2 configuration probes are passed as defines) | `android/external/boost` |
| 2 | Upstream pins `VSOMEIP_BOOST_VERSION=107500` | Patch: `108300`, matching the Boost above | `android/external/vsomeip/patches` |
| 3 | Socket base path `/vendor/run/someip/` and default config `/vendor/run/etc/` do not exist on Android | Patch: `/dev/socket/someip/` (tmpfs, usable by the `early_hal` Vehicle HAL before `/data` is mounted; created by init), config in `/vendor/etc/vsomeip` | patch, `android/someipd/ccg_someipd.rc` |
| 4 | No routing manager daemon in the upstream `Android.bp` | `ccg_someipd`: hosts the vsomeip routing manager (owns SOME/IP-SD and the network endpoints), logs to logcat | `app/someipd_main.cpp` |
| 5 | **SOME/IP-SD never starts on Android**: vsomeip waits for a kernel route covering the SD multicast address on its interface; netd only programs routes for networks ConnectivityService manages | `ccg_someipd --net-if` installs `224.0.0.0/4 dev <if>` via rtnetlink and restores it after link changes | `platform/linux/network_setup.*` |
| 6 | The vehicle network must not be managed by ConnectivityService (DHCP, own routing tables) | RRO limits `config_ethernet_iface_regex` to the user-facing interface; `ccg_someipd --net-address` brings the link up and assigns the static address | `android/overlay`, rc file |
| 7 | Local IPC, network, netlink and init need SELinux rules | `ccg_someipd` domain, `someip_socket` type, `someip_domain` attribute for every vsomeip application (VHAL included) | `android/sepolicy` |
| 8 | Android has no SOME/IP-aware property service | VHAL backend (`IVehicleHardware`) on the AOSP `DefaultVehicleHal` | `android/vhal`, `ivi/` |
| 9 | Google's SDV trees contain `external/sdv/vsomeip` with the same module names | `remove-project` hint in the local manifest | `android/manifests` |

Findings that apply to vsomeip in general (both ECUs), found in the two-ECU test (§7):

- **Client IDs encode the ECU.** vsomeip accepts a RESPONSE only if the high byte of
  the client ID equals the local `diagnosis` address, and a REQUEST only if it does
  not. Every ECU needs its own `diagnosis` value and application IDs in that range
  (HPC `0x10` / `0x10xx`, IVI `0x20` / `0x20xx`). With the default (`0x01`) on both
  sides all requests are dropped (`rmi::on_message: Invalid client id`).
- **`offer_event(..., update_on_change = false)` means "only on the vsomeip cycle"**;
  with no cycle nothing but the initial field value is ever sent. The HPC binding
  keeps it `true` and forces every notification, as the S2S gateway does its own
  timing.
- **UNIX socket paths are limited to 108 bytes**: a long `VSOMEIP_BASE_PATH` aborts
  the application (`File name too long`).
- vsomeip excludes its SOME/IP E2E plug-in on Android (`#ifndef ANDROID` in the
  routing manager). The S2S services do not use SOME/IP E2E (CAN E2E is checked on
  the HPC and reported as `E2E_ERROR` status), so nothing is lost.

## 3. Components

### 3.1 IVI client (portable, `ivi/`)

`ccg_ivi` has no OS or stack dependency and is unit tested on the host against
the real `S2SGateway` (`tests/ivi_harness.hpp`).

- `vehicle_services.hpp` – typed view of the HPC interface: every element as
  `Measured<T>{value, quality}`, quality = the HPC signal status (`VALID`,
  `INVALID`, `TIMEOUT`, `E2E_ERROR`, `NOT_AVAILABLE`). Decoders tolerate trailing
  bytes (newer minor versions) and map unknown status values to `INVALID`.
- `vehicle_client.hpp` – proxy of the four services: availability, cached
  values, method calls with request supervision (timeout, service loss, SOME/IP
  error → `CallStatus`). When a service becomes available its fields are read
  with their getters, so the client does not depend on initial events. Thread
  safe: vsomeip delivers on its dispatcher threads, the VHAL calls on binder
  threads; callbacks run without the lock held.
- `vehicle_property_bridge.hpp` – Android VHAL semantics with the AIDL numeric
  values (property IDs, areas, status codes), so the Android adapter only
  converts structures.

### 3.2 vsomeip adapters (`platform/vsomeip/`)

- `VsomeipClientTransport` (IVI) – requests the services, registers events,
  subscribes the eventgroups, forwards availability and messages; returns the
  session ID vsomeip assigns so responses can be matched.
- `VsomeipServerBinding` (HPC) – `s2s::ISomeIpBinding` with SOME/IP-SD; queues
  requests and subscriptions from vsomeip threads to the single-threaded gateway
  executor (eventfd), keeps the request objects for the responses, sends initial
  field values with `notify_one`.

### 3.3 Android integration (`android/`)

| Path | Content |
|------|---------|
| `manifests/ccg_ivi_vsomeip.xml` | repo local manifest: COVESA vsomeip 3.7.6 → `external/vsomeip`, this repository → `vendor/ccg/central-control-gateway` |
| `setup_aosp.sh` | applies the vsomeip patches, installs Boost into `external/boost` (idempotent) |
| `external/vsomeip/patches/` | Android patch for vsomeip 3.7.6 (paths, Boost version) |
| `external/boost/` | `fetch_boost.sh` (pinned SHA-256) and the `Android.bp` template |
| `../Android.bp` (repository root) | `libccg_ivi`, `libccg_vsomeip_client`, `ccg_someipd`, `ccg_ivi_vehicle_client`, `ccg_vsomeip_ivi.json`, `ccg_s2s_ivi_tests` |
| `someipd/ccg_someipd.rc` | `/dev/socket/someip`, service `vendor.ccg.someipd` (`early_hal`, `system`, `NET_ADMIN`) |
| `vhal/` | `android.hardware.automotive.vehicle-ccg-service`: `DefaultVehicleHal` + `SomeIpVehicleHardware`, init rc, VINTF fragment |
| `sepolicy/` | `ccg_someipd`, `someip_socket`, `someip_domain`, VHAL additions |
| `overlay/CcgIviConnectivityOverlay` | keeps the vehicle interface out of EthernetService |
| `products/` | `ccg_ivi.mk` (packages), `BoardConfigCcg.mk` (sepolicy) |

## 4. Integration into the IVI AOSP tree

Target: Android 14 or later (per-area access in `VehicleAreaConfig`).

1. Copy `android/manifests/ccg_ivi_vsomeip.xml` to `.repo/local_manifests/`
   (uncomment the `remove-project` for `external/sdv/vsomeip` if the tree has it), `repo sync`.
2. `vendor/ccg/central-control-gateway/android/setup_aosp.sh`
   – patches `external/vsomeip`, installs Boost 1.83 into `external/boost`.
   If the tree already has an `external/boost` providing `libboost_system` /
   `libboost_filesystem`, the script leaves it alone; then set
   `VSOMEIP_BOOST_VERSION` in `external/vsomeip/Android.bp` to its version.
3. Device makefile: `$(call inherit-product, vendor/ccg/central-control-gateway/android/products/ccg_ivi.mk)`
   and remove the reference VHAL (`android.hardware.automotive.vehicle@V*-default-service`).
   BoardConfig: `include vendor/ccg/central-control-gateway/android/products/BoardConfigCcg.mk`.
4. Board specifics:
   - `android/someipd/ccg_someipd.rc`: `--net-if` / `--net-address` = vehicle
     Ethernet interface or VLAN (e.g. `eth1`, `eth0.10`) and the IVI address.
     If ConnectivityService manages the interface instead (static IP via
     `config_ethernet_interfaces`), drop `--net-address` but keep `--net-if`
     for the SD route.
   - `config/vsomeip/ivi_vehicle.json`: `unicast` = the IVI address.
   - `android/overlay/.../config.xml`: regex of the interfaces EthernetService may manage.
   - `android/vhal/vhal-ccg-service.xml`: VHAL AIDL version of the release (2 = Android 14, 3 = Android 15).
5. `m` and flash. Optional: `atest ccg_s2s_ivi_tests` (unit tests on target and host).

## 5. Vehicle HAL properties

| VHAL property | Area | Source (HPC) | Access | Notes |
|---------------|------|--------------|--------|-------|
| `PERF_VEHICLE_SPEED` | global | VehicleMotionService.VehicleDynamics.vehicleSpeedKph | R, continuous ≤ 50 Hz | km/h → m/s |
| `PERF_STEERING_ANGLE` | global | VehicleMotionService.SteeringWheel.angleDeg | R, continuous ≤ 50 Hz | road wheel angle = steering wheel / ratio (15), left negative |
| `DOOR_POS` | 4 doors, rear (trunk) | BodyService.DoorStatus | R, trunk RW | 0 closed, 1 ajar, 2 open; writing > 0 to the trunk calls `OpenTrunk` |
| `DOOR_LOCK` | 4 doors | BodyService.DoorStatus.centralLock | RW | central lock: any door area calls `SetCentralLock`; the new state comes back from the BCM |
| `EV_BATTERY_LEVEL` | global | EnergyService.BatteryStatus.socPercent | R, continuous ≤ 10 Hz | SoC × `INFO_EV_BATTERY_CAPACITY` (Wh) |
| `EV_BATTERY_INSTANTANEOUS_CHARGE_RATE` | global | packVoltage × packCurrent | R, continuous ≤ 10 Hz | mW, positive = charging |
| `INFO_EV_BATTERY_CAPACITY` | global | configuration | R, static | 75 kWh (`BridgeOptions`) |
| `HVAC_TEMPERATURE_SET` | row 1 left + right | ClimateService.SetCabinClimate | RW | 16–32 °C, 0.5 °C steps; no HPC feedback, the confirmed set-point is reported |
| `HVAC_FAN_SPEED` | row 1 left + right | ClimateService.SetCabinClimate | RW | 0–7 |

Status mapping: `VALID` → `AVAILABLE`; `TIMEOUT` / `NOT_AVAILABLE` / service not
offered → `UNAVAILABLE` (`getValues`: `NOT_AVAILABLE`); `INVALID` / `E2E_ERROR`
→ `ERROR` (`getValues`: `INTERNAL_ERROR`). Write results: HPC `E_NOT_OK`
(outside the CAN signal range) → `INVALID_ARG`, timeout / not sent → `TRY_AGAIN`,
service not offered → `NOT_AVAILABLE`.

On-change properties are pushed as property events (only on a change of value
or status). Continuous properties are served from the cache through
`getValues`, which `DefaultVehicleHal` polls at the subscribed sample rate;
only their status changes are pushed. Vehicle-specific conventions (steering
ratio and sign, BMS current sign, HVAC area, battery capacity, climate init
values) are `BridgeOptions`.

## 6. Bring-up and diagnosis on the target

```sh
adb logcat -s ccg_someipd ccg_vhal vsomeip          # routing daemon, VHAL, vsomeip
adb shell dumpsys android.hardware.automotive.vehicle.IVehicle/default   # services, counters, all values
adb shell ip route show table all | grep 224.        # SD route present?
adb root && adb shell ccg_ivi_vehicle_client --duration-s 10 --lock   # debug builds
```

| Symptom | Cause |
|---------|-------|
| No `Route "eth1" state changed: up` / `SOME/IP routing ready.` in the log, no service ever available | no multicast route on the vsomeip interface (`--net-if` missing / wrong interface / no `NET_ADMIN`) |
| `rmi::on_message: Invalid client id` | `diagnosis` address / application IDs not unique per ECU (§2) |
| `File name too long` abort | `VSOMEIP_BASE_PATH` too long |
| `... is not configured as "routing"` | `--app` of `ccg_someipd` differs from `routing` in the JSON |
| Properties `NOT_AVAILABLE`, `dumpsys` shows services "NOT available" | HPC not offering (check SD with `tcpdump -i eth1 udp port 30490`) |
| Values `ERROR` | HPC reports `INVALID` / `E2E_ERROR` for the CAN signal – a vehicle-side problem |

## 7. Verification

Done in this repository's CI-less environment (Linux host, vsomeip 3.7.6 built
from source):

- **Unit tests** (`ccg_s2s_ivi_tests`, 61 tests): codec, client (availability, field
  refresh, timeouts, service loss, late responses, header checks), VHAL mapping
  (IDs, configs, unit conversions, status mapping, on-change filtering, writes),
  all against the real `S2SGateway`; also with GCC ASan/UBSan and Clang `-Werror`.
- **Two-ECU test** `tools/ivi_hpc_netns_test.sh` (root): HPC and IVI in separate
  network namespaces linked by a veth pair, SOME/IP-SD over multicast. The HPC
  runs the S2S gateway on vsomeip with simulated ECUs (closed-loop BCM). The IVI
  interface starts down, without address or multicast route, like an unmanaged
  interface on Android. Checked: no service without the SD route (the Android
  failure mode), `ccg_someipd` configures link, address and route, discovery of
  all four services, events and fields as VHAL properties, lock / climate /
  trunk writes reaching the CAN bus and the lock state coming back, HPC
  restart, link flap, no re-apply storm.
- **VHAL adapter**: `SomeIpVehicleHardware` compiled against stub headers of the
  AOSP `IVehicleHardware` API and run against the HPC bench in the IVI namespace
  (`getValues`, `setValues`, `dump`).
- **Android build inputs**: Blueprint files parsed with `bpfmt`; the vsomeip
  patch applies to the 3.7.6 tag; `setup_aosp.sh` run on a mock tree; Boost.System /
  Filesystem compiled with exactly the `Android.bp` flags and vsomeip's sources
  (Android configuration header) compiled against the assembled Boost tree without
  falling back to system headers; the SELinux policy compiled with `checkpolicy`
  together with the Android 14 `system/sepolicy` (public, private, vendor;
  neverallow checks active).

Not done here (no AOSP checkout or IVI hardware available): a full AOSP build,
the Treble compatibility / CTS / VTS suites, and a run on the target.

## 8. Limitations / next steps

- vsomeip security (policies per uid/gid) is off; enable it once the set of
  vsomeip applications on the IVI is fixed.
- The IVI configuration has fixed addresses; a production variant would be
  generated per vehicle line together with the S2S matrix.
- One HVAC zone; no climate feedback from the HPC (the confirmed set-point is reported).
- Apps that need SOME/IP services beyond VHAL properties need their own HAL
  (AIDL) on top of `VehicleClient`; apps cannot use vsomeip directly (SELinux,
  Treble).
