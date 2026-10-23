#!/usr/bin/env bash
# Prepares an AOSP tree for the IVI vsomeip port (run after 'repo sync'):
#   1. applies the Android patches to external/vsomeip (COVESA 3.7.6)
#   2. installs Boost 1.83 into external/boost unless the tree already has one
#
#   vendor/ccg/central-control-gateway/android/setup_aosp.sh [AOSP_ROOT] [BOOST_TARBALL]
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
AOSP=$(cd "${1:-$HERE/../../../..}" && pwd)
BOOST_TARBALL=${2:-}

[[ -d "$AOSP/external/vsomeip" ]] || { echo "no $AOSP/external/vsomeip (local manifest synced?)" >&2; exit 1; }

cd "$AOSP/external/vsomeip"
for patch in "$HERE"/external/vsomeip/patches/*.patch; do
    if git apply --reverse --check "$patch" 2>/dev/null; then
        echo "already applied: $(basename "$patch")"
    else
        git apply "$patch"
        echo "applied: $(basename "$patch")"
    fi
done

if [[ -e "$AOSP/external/boost/Android.bp" ]]; then
    echo "external/boost exists - make sure it provides libboost_system / libboost_filesystem"
    echo "and that VSOMEIP_BOOST_VERSION in external/vsomeip/Android.bp matches its version"
else
    "$HERE/external/boost/fetch_boost.sh" "$AOSP/external/boost" $BOOST_TARBALL
fi
