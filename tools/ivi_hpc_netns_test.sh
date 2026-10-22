#!/usr/bin/env bash
# Two-ECU integration test of the IVI vsomeip port against the HPC S2S gateway.
#
#   ccg-hpc netns  10.0.0.10 eth0  <--veth-->  eth1 10.0.0.20  ccg-ivi netns
#   ccg_hpc_vsomeip_bench                      ccg_someipd (routing manager, SD route)
#   (S2S gateway + virtual CAN bus)            ccg_ivi_vehicle_client (VHAL stack)
#
# The IVI namespace starts without any multicast route, as on Android, so SOME/IP-SD
# only comes up if ccg_someipd installs it. Needs root (ip netns) and a build with
# vsomeip (cmake -DCCG_WITH_VSOMEIP=ON -DCMAKE_PREFIX_PATH=<vsomeip install>).
#
#   sudo [CCG_TEST_LOGDIR=dir] tools/ivi_hpc_netns_test.sh [BUILD_DIR] [VSOMEIP_LIB_DIR]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD=$(cd "${1:-$ROOT/build}" && pwd)
LIBDIR=${2:-}
WORK=$(mktemp -d /tmp/ccg-ivi.XXXXXX)
HPC=ccg-hpc
IVI=ccg-ivi

[[ -n "$LIBDIR" ]] && export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
for bin in ccg_hpc_vsomeip_bench ccg_someipd ccg_ivi_vehicle_client; do
    [[ -x "$BUILD/$bin" ]] || { echo "missing $BUILD/$bin (build with vsomeip)"; exit 2; }
done

pids=()
cleanup() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    ip netns del "$HPC" 2>/dev/null || true
    ip netns del "$IVI" 2>/dev/null || true
    if [[ -n "${CCG_TEST_LOGDIR:-}" ]]; then mkdir -p "$CCG_TEST_LOGDIR" && cp "$WORK"/*.log "$CCG_TEST_LOGDIR"/; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    for f in "$WORK"/*.log; do echo "----- $(basename "$f")"; tail -n 40 "$f"; done
    exit 1
}

# --- vehicle network -----------------------------------------------------------
ip netns add "$HPC"
ip netns add "$IVI"
ip link add eth0 netns "$HPC" type veth peer name eth1 netns "$IVI"
ip -n "$HPC" addr add 10.0.0.10/24 dev eth0
ip -n "$IVI" addr add 10.0.0.20/24 dev eth1
for ns in "$HPC" "$IVI"; do ip -n "$ns" link set lo up; done
ip -n "$HPC" link set eth0 up
ip -n "$IVI" link set eth1 up
# A Linux HPC has its multicast route; the IVI (Android) has none.
ip -n "$HPC" route add 224.0.0.0/4 dev eth0
if ip -n "$IVI" route show table all | grep -q '^224\.'; then fail "IVI unexpectedly has a multicast route"; fi

# vsomeip puts its UNIX sockets there: keep the path short (sun_path is 108 bytes).
mkdir -p "$WORK/hpc" "$WORK/ivi"
# exec: started with '&', $! must be the program itself (not a subshell) so that
# kill reaches it. Foreground calls therefore run in ( ).
run_hpc() { exec ip netns exec "$HPC" env VSOMEIP_BASE_PATH="$WORK/hpc/" \
    VSOMEIP_CONFIGURATION="$ROOT/config/vsomeip/hpc_s2s_gateway.json" "$@"; }
run_ivi() { exec ip netns exec "$IVI" env VSOMEIP_BASE_PATH="$WORK/ivi/" \
    VSOMEIP_CONFIGURATION="$ROOT/config/vsomeip/ivi_vehicle.json" "$@"; }

# --- HPC ------------------------------------------------------------------------
run_hpc "$BUILD/ccg_hpc_vsomeip_bench" > "$WORK/hpc.log" 2>&1 &
pids+=($!)

# --- IVI without SD route (stock Android): vsomeip never starts SOME/IP-SD --------
run_ivi "$BUILD/ccg_someipd" > "$WORK/someipd-noroute.log" 2>&1 &
noroute=$!
sleep 1
if (run_ivi "$BUILD/ccg_ivi_vehicle_client" --expect-all-services --duration-s 3 \
        > "$WORK/client-noroute.log" 2>&1); then
    fail "services found although the IVI has no multicast route"
fi
kill "$noroute"; wait "$noroute" 2>/dev/null || true
grep -q 'service 0x600[1-4] available' "$WORK/client-noroute.log" && fail "unexpected availability"
echo "ok: without the SD route the IVI finds no service (the Android failure mode)"

# --- IVI: routing daemon first (as started by init), then the VHAL-side client ----
run_ivi "$BUILD/ccg_someipd" --sd-route eth1 > "$WORK/someipd.log" 2>&1 &
pids+=($!)
sleep 1
ip -n "$IVI" route show 224.0.0.0/4 | grep -q 'dev eth1' || fail "ccg_someipd did not install the SD route"
echo "ok: SD multicast route installed on the IVI by ccg_someipd"

set +e
(run_ivi "$BUILD/ccg_ivi_vehicle_client" --expect-all-services --lock --climate 23.5:4 --trunk \
    --duration-s 8 > "$WORK/client.log" 2>&1)
rc=$?
set -e
[[ $rc -eq 0 ]] || fail "ccg_ivi_vehicle_client exited with $rc"

expect() {  # file, pattern, description
    grep -Eq "$2" "$WORK/$1" || fail "$3 (no '$2' in $1)"
    echo "ok: $3"
}
expect client.log 'service 0x6001 available' "VehicleMotionService discovered via SOME/IP-SD"
expect client.log 'service 0x6004 available' "ClimateService discovered"
expect client.log 'PERF_VEHICLE_SPEED [0-9]+\.' "vehicle speed received as VHAL property"
expect client.log 'PERF_STEERING_ANGLE -3\.0' "steering wheel 45 deg -> road wheel -3 deg"
expect client.log 'EV_BATTERY_LEVEL 57300\.' "battery level 76.4 % of 75 kWh"
expect client.log 'DOOR_POS\[0x40\] 1 ' "rear right door ajar"
expect client.log 'command lock: OK' "DOOR_LOCK write accepted by the HPC"
expect hpc.log 'TX HPC_BodyCommand HPC_CentralLockReq=1' "lock request on the CAN bus"
expect client.log 'DOOR_LOCK\[0x1\] 1 ' "BCM lock state back on the IVI (closed loop)"
expect client.log 'command temperature 23.5: OK' "HVAC_TEMPERATURE_SET write"
expect client.log 'command fan 4: OK' "HVAC_FAN_SPEED write"
expect hpc.log 'HPC_CabinTempSetpt=23\.5.* HPC_FanLevel=4' "climate set-point and fan level on the CAN bus"
expect client.log 'command trunk: OK' "trunk open request"
expect client.log 'DOOR_POS\[0x20000000\] 2 ' "trunk open reported back"
expect client.log 'malformed=0 .* timeouts=0' "no malformed messages, no timeouts"

# --- HPC restart: the IVI must notice the loss (TTL / StopOffer) and recover -------
kill "${pids[0]}"
wait "${pids[0]}" 2>/dev/null || true
run_ivi "$BUILD/ccg_ivi_vehicle_client" --duration-s 6 > "$WORK/client2.log" 2>&1 &
client2=$!
sleep 2
run_hpc "$BUILD/ccg_hpc_vsomeip_bench" > "$WORK/hpc2.log" 2>&1 &
pids+=($!)
wait "$client2" || true
expect client2.log 'service 0x6002 available' "IVI finds the HPC after it was (re)started"
expect client2.log 'DOOR_LOCK\[0x1\] 0 ' "fresh field values after the HPC restart"

echo "PASS"
