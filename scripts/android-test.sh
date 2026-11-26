#!/usr/bin/env bash
#
# Build the test suites for Android and run them on a connected device or emulator.
#
# Usage:
#   scripts/android-test.sh [aarch64|x86_64]   # default: aarch64
#
# Requires:
#   - Swift toolchain matching the Swift SDK for Android (swift / SWIFT env var)
#   - Swift SDK for Android installed and linked to the NDK (setup-android-sdk.sh)
#   - ANDROID_NDK_HOME pointing at the NDK
#   - adb on PATH with exactly one device/emulator attached
#
# Environment:
#   SWIFT          swift command to use (default: "swift")
#   SWIFT_SDK_ID   Swift SDK id (default: swift-6.4.3-RELEASE_android)
#   API_LEVEL      Android API level in the target triple (default: 23)

set -euo pipefail

ARCH="${1:-aarch64}"
SWIFT="${SWIFT:-swift}"
SWIFT_SDK_ID="${SWIFT_SDK_ID:-swift-6.4.3-RELEASE_android}"
API_LEVEL="${API_LEVEL:-23}"
TRIPLE="${ARCH}-unknown-linux-android${API_LEVEL}"
DEVICE_DIR="/data/local/tmp/swiftargon2-tests"
SUITES=(Blake2bTests Argon2Tests CReferenceTests)

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must be set}"

cd "$(dirname "$0")/.."

echo "Building tests for ${TRIPLE}..."
# Swift Testing ships only as a shared library in the Android SDK,
# so tests build against the dynamic Swift stdlib.
$SWIFT build --build-tests --swift-sdk "$SWIFT_SDK_ID" --triple "$TRIPLE"

BIN_PATH="$($SWIFT build --build-tests --swift-sdk "$SWIFT_SDK_ID" --triple "$TRIPLE" --show-bin-path)"

# SwiftPM's default Swift SDK locations: macOS, then Linux.
SDK_BUNDLE=""
for dir in "$HOME/Library/org.swift.swiftpm/swift-sdks" "$HOME/.swiftpm/swift-sdks" "${XDG_CONFIG_HOME:-$HOME/.config}/swiftpm/swift-sdks"; do
    if [[ -d "${dir}/${SWIFT_SDK_ID}.artifactbundle" ]]; then
        SDK_BUNDLE="${dir}/${SWIFT_SDK_ID}.artifactbundle"
        break
    fi
done
[[ -n "$SDK_BUNDLE" ]] || { echo "error: ${SWIFT_SDK_ID}.artifactbundle not found in SwiftPM's swift-sdks directories" >&2; exit 1; }
SWIFT_LIBS="${SDK_BUNDLE}/swift-android/swift-resources/usr/lib/swift-${ARCH}/android"

LIBCXX="$(ls "${ANDROID_NDK_HOME}"/toolchains/llvm/prebuilt/*/sysroot/usr/lib/"${ARCH}"-linux-android/libc++_shared.so | head -n 1)"

echo "Pushing test binaries and runtime libraries to ${DEVICE_DIR}..."
adb shell rm -rf "$DEVICE_DIR"
adb shell mkdir -p "$DEVICE_DIR"
adb push "$SWIFT_LIBS"/*.so "$LIBCXX" "$DEVICE_DIR/" >/dev/null
for suite in "${SUITES[@]}"; do
    adb push "${BIN_PATH}/${suite}-test-runner" "${BIN_PATH}/${suite}.so" "$DEVICE_DIR/" >/dev/null
done

status=0
for suite in "${SUITES[@]}"; do
    echo ""
    echo "=== ${suite} (${TRIPLE}) ==="
    if ! adb shell "cd ${DEVICE_DIR} && LD_LIBRARY_PATH=${DEVICE_DIR} ./${suite}-test-runner --testing-library swift-testing"; then
        echo "error: ${suite} failed" >&2
        status=1
    fi
done

adb shell rm -rf "$DEVICE_DIR"
exit $status
