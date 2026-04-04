#!/bin/bash
# Run all tests using Swift Package Manager
# Usage: ./test.sh

set -e

cd "$(dirname "$0")"

echo "Running SwiftArgon2 tests..."
echo ""

swift test

echo ""
echo "All tests passed!"
