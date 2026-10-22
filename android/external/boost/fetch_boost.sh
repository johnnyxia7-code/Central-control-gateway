#!/usr/bin/env bash
# Populates AOSP external/boost with the Boost subset vsomeip needs:
# all headers (Asio, ICL, Property Tree, Stacktrace, ... are header-only) and
# the sources of Boost.System / Boost.Filesystem, plus Android.bp.template next
# to this script as Android.bp (a template, so that Soong does not parse it in
# this repository).
#
#   android/external/boost/fetch_boost.sh <AOSP_ROOT>/external/boost [TARBALL]
#
# Only needed when the tree has no external/boost yet; an existing one must
# provide libboost_system / libboost_filesystem (see docs/IVI_ANDROID_VSOMEIP.md).
set -euo pipefail

VERSION=1.83.0
SHA256=c5a0688e1f0c05f354bbd0b32244d36085d9ffc9f932e8a18983a9908096f614
URL="https://github.com/boostorg/boost/releases/download/boost-${VERSION}/boost-${VERSION}.tar.xz"

DEST=${1:?usage: $0 <AOSP_ROOT>/external/boost [boost-${VERSION}.tar.xz]}
TARBALL=${2:-}
HERE=$(cd "$(dirname "$0")" && pwd)

if [[ -e "$DEST/Android.bp" ]]; then
    echo "$DEST already contains an Android.bp - refusing to overwrite" >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [[ -z "$TARBALL" ]]; then
    TARBALL="$TMP/boost-${VERSION}.tar.xz"
    echo "downloading $URL"
    curl -fsSL -o "$TARBALL" "$URL"
fi
echo "$SHA256  $TARBALL" | sha256sum -c -

tar -xJf "$TARBALL" -C "$TMP"
SRC="$TMP/boost-${VERSION}"

mkdir -p "$DEST/boost" "$DEST/libs/system" "$DEST/libs/filesystem"
# The release archive is modular (libs/<lib>/include/boost/...): merge all
# public headers into one tree, as 'b2 headers' would.
for inc in "$SRC"/libs/*/include "$SRC"/libs/numeric/*/include; do
    [[ -d "$inc/boost" ]] && cp -R "$inc/boost/." "$DEST/boost/"
done
cp -R "$SRC/libs/system/src" "$DEST/libs/system/"
cp -R "$SRC/libs/filesystem/src" "$DEST/libs/filesystem/"
cp "$SRC/LICENSE_1_0.txt" "$DEST/"
cp "$HERE/Android.bp.template" "$DEST/Android.bp"
echo "boost ${VERSION} installed in $DEST ($(find "$DEST/boost" -type f | wc -l) headers)"
