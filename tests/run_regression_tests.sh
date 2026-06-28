#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python}"
SCANNER="$ROOT_DIR/src/elf_capability_mapper.py"
OUT_DIR="$ROOT_DIR/tests/out"

mkdir -p "$OUT_DIR"

"$ROOT_DIR/scripts/build_samples.sh" >/dev/null

"$PYTHON_BIN" "$SCANNER" \
  "$ROOT_DIR/samples/bin/hello" \
  --json "$OUT_DIR/hello.json" >/dev/null

"$PYTHON_BIN" "$SCANNER" \
  "$ROOT_DIR/samples/bin/capability_demo" \
  --json "$OUT_DIR/capability_demo.json" >/dev/null

"$PYTHON_BIN" "$SCANNER" \
  "$ROOT_DIR/samples/bin/string_indicator_demo" \
  --json "$OUT_DIR/string_indicator_demo.json" >/dev/null

"$PYTHON_BIN" - \
  "$OUT_DIR/hello.json" \
  "$OUT_DIR/capability_demo.json" \
  "$OUT_DIR/string_indicator_demo.json" <<'PY'
import json
import sys
from pathlib import Path

hello = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
demo = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
string_demo = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))

expected_capability_symbols = {
    "ptrace",
    "system",
    "mprotect",
    "execve",
    "dlopen",
    "dlsym",
    "socket",
    "connect",
    "send",
    "recv",
}

expected_string_markers = {
    "/proc/self/status",
    "LD_PRELOAD",
    "/bin/sh",
    "curl",
    "wget",
}

actual_capability_symbols = {
    indicator["symbol"]
    for indicator in demo["capability_indicators"]
}

actual_string_markers = {
    indicator["string"]
    for indicator in string_demo["embedded_string_indicators"]
}

if hello["capability_indicators"]:
    raise SystemExit(
        "Safe hello fixture unexpectedly produced capability indicators."
    )

if hello["embedded_string_indicators"]:
    raise SystemExit(
        "Safe hello fixture unexpectedly produced string indicators."
    )

if string_demo["capability_indicators"]:
    raise SystemExit(
        "String fixture unexpectedly produced capability indicators."
    )

if actual_capability_symbols != expected_capability_symbols:
    missing = sorted(expected_capability_symbols - actual_capability_symbols)
    unexpected = sorted(actual_capability_symbols - expected_capability_symbols)
    raise SystemExit(
        "Capability-indicator mismatch. "
        f"Missing: {missing}; Unexpected: {unexpected}"
    )

if actual_string_markers != expected_string_markers:
    missing = sorted(expected_string_markers - actual_string_markers)
    unexpected = sorted(actual_string_markers - expected_string_markers)
    raise SystemExit(
        "Embedded-string mismatch. "
        f"Missing: {missing}; Unexpected: {unexpected}"
    )

for label, report in (
    ("hello", hello),
    ("capability_demo", demo),
    ("string_indicator_demo", string_demo),
):
    hardening = report["hardening"]

    if hardening["gnu_relro_segment"] is not True:
        raise SystemExit(f"{label}: GNU RELRO segment was not detected.")

    if hardening["executable_stack"] is not False:
        raise SystemExit(f"{label}: expected a non-executable stack.")

    if hardening["pie_candidate"] is not True:
        raise SystemExit(f"{label}: expected PIE-candidate status.")

if hello["hardening"]["stack_canary_import"] is not False:
    raise SystemExit("hello: unexpected stack-canary import.")

if demo["hardening"]["stack_canary_import"] is not True:
    raise SystemExit("capability_demo: expected stack-canary import.")

if string_demo["hardening"]["stack_canary_import"] is not False:
    raise SystemExit(
        "string_indicator_demo: unexpected stack-canary import."
    )

print(
    "Regression assertions passed: safe fixture has 0 indicators; "
    "capability fixture has 10 expected imports; "
    "string fixture has 5 expected markers; "
    "hardening signals matched expectations."
)
PY

set +e
non_elf_output="$("$PYTHON_BIN" "$SCANNER" README.md 2>&1)"
non_elf_status=$?
set -e

if [[ "$non_elf_status" -ne 2 ]]; then
  echo "Expected non-ELF exit code 2, received $non_elf_status." >&2
  exit 1
fi

if [[ "$non_elf_output" != *"not a valid ELF file"* ]]; then
  echo "Expected non-ELF validation message was not found." >&2
  exit 1
fi


INVALID_CONFIG="$ROOT_DIR/tests/fixtures/invalid-indicators.json"

set +e
invalid_config_output="$(
  "$PYTHON_BIN" "$SCANNER" \
    "$ROOT_DIR/samples/bin/hello" \
    --config "$INVALID_CONFIG" 2>&1
)"
invalid_config_status=$?
set -e

if [[ "$invalid_config_status" -ne 2 ]]; then
  echo "Expected invalid-config exit code 2, received $invalid_config_status." >&2
  exit 1
fi

if [[ "$invalid_config_output" != *"is missing: message"* ]]; then
  echo "Expected invalid-config validation message was not found." >&2
  exit 1
fi

echo "Malformed configuration rejection test passed."

echo "Regression test passed."
