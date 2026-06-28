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

"$PYTHON_BIN" - "$OUT_DIR/hello.json" "$OUT_DIR/capability_demo.json" <<'PY'
import json
import sys
from pathlib import Path

hello = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
demo = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

expected_symbols = {
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

actual_symbols = {
    indicator["symbol"]
    for indicator in demo["capability_indicators"]
}

if hello["capability_indicators"]:
    raise SystemExit(
        "Safe hello fixture unexpectedly produced capability indicators."
    )

if actual_symbols != expected_symbols:
    missing = sorted(expected_symbols - actual_symbols)
    unexpected = sorted(actual_symbols - expected_symbols)
    raise SystemExit(
        "Capability-indicator mismatch. "
        f"Missing: {missing}; Unexpected: {unexpected}"
    )

for label, report in (("hello", hello), ("capability_demo", demo)):
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

print(
    "Regression assertions passed: safe fixture has 0 indicators; "
    "capability fixture has 10 expected indicators; "
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

echo "Regression test passed."
