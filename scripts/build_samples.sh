#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/samples/source"
BINARY_DIR="$ROOT_DIR/samples/bin"

mkdir -p "$BINARY_DIR"

gcc -O0 -fno-builtin -fno-inline -Wall -Wextra \
  "$SOURCE_DIR/hello.c" \
  -o "$BINARY_DIR/hello"

gcc -O0 -fno-builtin -fno-inline -fstack-protector-strong -Wall -Wextra \
  "$SOURCE_DIR/capability_demo.c" \
  -ldl \
  -o "$BINARY_DIR/capability_demo"

echo "Built sample binaries:"
file "$BINARY_DIR/hello" "$BINARY_DIR/capability_demo"
