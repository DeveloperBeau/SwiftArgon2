#!/bin/bash
#
# Run the Argon2 Swift vs C performance benchmark
#
# Usage:
#   ./benchmark.sh           # Full benchmark
#   ./benchmark.sh --quick   # Quick benchmark (fewer configurations)
#   ./benchmark.sh -q        # Quick benchmark (short flag)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building benchmark in release mode..."
swift build -c release --product Benchmark

echo ""
echo "Running benchmark..."
.build/release/Benchmark "$@"
