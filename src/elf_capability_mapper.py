#!/usr/bin/env python3
"""
ELF Capability Mapper
Stage 3: Static metadata, imports, capability indicators, and hardening signals.

This tool reads ELF files without executing them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


CHUNK_SIZE = 65536
PF_X = 0x1

CAPABILITY_MAP: dict[str, dict[str, str]] = {
    "ptrace": {
        "severity": "MEDIUM",
        "category": "anti-analysis",
        "message": "Debugger-interaction capability may be present.",
    },
    "system": {
        "severity": "MEDIUM",
        "category": "command-execution",
        "message": "Shell command execution capability may be present.",
    },
    "popen": {
        "severity": "MEDIUM",
        "category": "command-execution",
        "message": "Command execution through a pipe may be present.",
    },
    "execve": {
        "severity": "MEDIUM",
        "category": "process-execution",
        "message": "Direct process execution capability may be present.",
    },
    "execl": {
        "severity": "MEDIUM",
        "category": "process-execution",
        "message": "Process execution capability may be present.",
    },
    "execvp": {
        "severity": "MEDIUM",
        "category": "process-execution",
        "message": "Process execution capability may be present.",
    },
    "dlopen": {
        "severity": "LOW",
        "category": "dynamic-loading",
        "message": "Runtime shared-library loading capability may be present.",
    },
    "dlsym": {
        "severity": "LOW",
        "category": "dynamic-loading",
        "message": "Runtime symbol lookup capability may be present.",
    },
    "socket": {
        "severity": "LOW",
        "category": "networking",
        "message": "Network socket capability may be present.",
    },
    "connect": {
        "severity": "LOW",
        "category": "networking",
        "message": "Outbound network connection capability may be present.",
    },
    "send": {
        "severity": "LOW",
        "category": "networking",
        "message": "Network data transmission capability may be present.",
    },
    "recv": {
        "severity": "LOW",
        "category": "networking",
        "message": "Network data reception capability may be present.",
    },
    "mprotect": {
        "severity": "MEDIUM",
        "category": "memory-protection",
        "message": "Memory-permission modification capability may be present.",
    },
}


def calculate_sha256(path: Path) -> str:
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


def get_interpreter(elf: ELFFile) -> str | None:
    """Return the ELF program interpreter, when present."""
    for segment in elf.iter_segments():
        if str(segment["p_type"]) == "PT_INTERP":
            raw_value = segment.data()
            return raw_value.split(b"\x00", 1)[0].decode(
                "utf-8",
                errors="replace",
            )

    return None


def get_needed_libraries(elf: ELFFile) -> list[str]:
    """Return unique shared libraries listed in ELF dynamic sections."""
    libraries: list[str] = []

    for section in elf.iter_sections():
        if str(section["sh_type"]) != "SHT_DYNAMIC":
            continue

        for tag in section.iter_tags():
            if str(tag.entry.d_tag) != "DT_NEEDED":
                continue

            library_name = getattr(tag, "needed", None)

            if library_name:
                libraries.append(str(library_name))

    return sorted(set(libraries))


def normalize_symbol_name(symbol_name: str) -> str:
    """Remove symbol-version information when present."""
    return symbol_name.split("@", 1)[0]


def get_dynamic_imports(elf: ELFFile) -> list[str]:
    """Return undefined symbols imported through the dynamic symbol table."""
    dynamic_symbols = elf.get_section_by_name(".dynsym")

    if dynamic_symbols is None:
        return []

    imports: list[str] = []

    for symbol in dynamic_symbols.iter_symbols():
        symbol_name = normalize_symbol_name(symbol.name)

        if not symbol_name:
            continue

        if str(symbol["st_shndx"]) == "SHN_UNDEF":
            imports.append(symbol_name)

    return sorted(set(imports))


def map_capability_indicators(imports: list[str]) -> list[dict[str, str]]:
    """Map selected imports to cautious analyst-facing indicators."""
    indicators: list[dict[str, str]] = []

    for symbol_name in imports:
        capability = CAPABILITY_MAP.get(symbol_name)

        if capability is None:
            continue

        indicators.append(
            {
                "severity": capability["severity"],
                "category": capability["category"],
                "symbol": symbol_name,
                "message": capability["message"],
            }
        )

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    return sorted(
        indicators,
        key=lambda item: (
            severity_order.get(item["severity"], 99),
            item["category"],
            item["symbol"],
        ),
    )


def get_hardening_signals(
    elf: ELFFile,
    imports: list[str],
    interpreter: str | None,
) -> dict[str, Any]:
    """Collect cautious hardening-related signals from ELF metadata."""
    has_gnu_relro = False
    gnu_stack_flags: int | None = None

    for segment in elf.iter_segments():
        segment_type = str(segment["p_type"])

        if segment_type == "PT_GNU_RELRO":
            has_gnu_relro = True

        if segment_type == "PT_GNU_STACK":
            gnu_stack_flags = int(segment["p_flags"])

    executable_stack = (
        None
        if gnu_stack_flags is None
        else bool(gnu_stack_flags & PF_X)
    )

    elf_type = str(elf["e_type"])
    pie_candidate = elf_type == "ET_DYN" and interpreter is not None

    return {
        "gnu_relro_segment": has_gnu_relro,
        "executable_stack": executable_stack,
        "stack_canary_import": "__stack_chk_fail" in imports,
        "pie_candidate": pie_candidate,
    }


def analyze_elf(path: Path) -> dict[str, Any]:
    """Collect static ELF metadata, imports, indicators, and hardening."""
    file_size = path.stat().st_size
    file_hash = calculate_sha256(path)

    with path.open("rb") as file_handle:
        elf = ELFFile(file_handle)
        interpreter = get_interpreter(elf)
        imports = get_dynamic_imports(elf)

        return {
            "file": str(path),
            "sha256": file_hash,
            "size_bytes": file_size,
            "elf_class": f"ELF{elf.elfclass}",
            "endianness": (
                "little-endian" if elf.little_endian else "big-endian"
            ),
            "architecture": str(elf["e_machine"]),
            "elf_type": str(elf["e_type"]),
            "entry_point": f"0x{elf['e_entry']:x}",
            "interpreter": interpreter,
            "needed_libraries": get_needed_libraries(elf),
            "import_count": len(imports),
            "imported_symbols": imports,
            "capability_indicators": map_capability_indicators(imports),
            "hardening": get_hardening_signals(
                elf,
                imports,
                interpreter,
            ),
        }


def format_stack_status(executable_stack: bool | None) -> str:
    """Return a readable executable-stack status."""
    if executable_stack is None:
        return "Not specified"

    if executable_stack:
        return "Executable (review recommended)"

    return "Non-executable"


def format_report(result: dict[str, Any]) -> str:
    """Format scan results for the terminal."""
    hardening = result["hardening"]

    lines = [
        "ELF Capability Mapper — Static Analysis Report",
        "=" * 48,
        f"File:          {result['file']}",
        f"SHA-256:       {result['sha256']}",
        f"Size:          {result['size_bytes']} bytes",
        f"ELF Class:     {result['elf_class']}",
        f"Endianness:    {result['endianness']}",
        f"Architecture:  {result['architecture']}",
        f"ELF Type:      {result['elf_type']}",
        f"Entry Point:   {result['entry_point']}",
        (
            f"Interpreter:   {result['interpreter']}"
            if result["interpreter"]
            else "Interpreter:   None detected"
        ),
        "",
        "Needed Shared Libraries:",
    ]

    libraries = result["needed_libraries"]

    if libraries:
        lines.extend(f"  - {library}" for library in libraries)
    else:
        lines.append("  - None detected")

    lines.extend(
        [
            "",
            "Hardening Signals:",
            (
                "  - GNU RELRO segment: "
                + ("Present" if hardening["gnu_relro_segment"] else "Not detected")
            ),
            (
                "  - Stack marking: "
                + format_stack_status(hardening["executable_stack"])
            ),
            (
                "  - Stack canary import: "
                + (
                    "Present"
                    if hardening["stack_canary_import"]
                    else "Not detected"
                )
            ),
            (
                "  - PIE candidate: "
                + (
                    "Yes (ET_DYN with interpreter)"
                    if hardening["pie_candidate"]
                    else "No"
                )
            ),
            "",
            f"Dynamic Imports: {result['import_count']}",
            "Capability Indicators:",
        ]
    )

    indicators = result["capability_indicators"]

    if not indicators:
        lines.append("  - No selected capability indicators detected.")
    else:
        for indicator in indicators:
            lines.append(
                "  - "
                f"[{indicator['severity']}] "
                f"{indicator['category']} via {indicator['symbol']}: "
                f"{indicator['message']}"
            )

    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Statically inspect a Linux ELF file without executing it."
        )
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Path to the ELF file to inspect.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        type=Path,
        help="Optional path for a JSON report.",
    )
    return parser.parse_args()


def main() -> int:
    """Run the ELF static inspection."""
    args = parse_arguments()
    target = args.target

    if not target.is_file():
        print(
            f"Error: target file not found: {target}",
            file=sys.stderr,
        )
        return 2

    try:
        result = analyze_elf(target)
    except ELFError:
        print(
            f"Error: '{target}' is not a valid ELF file.",
            file=sys.stderr,
        )
        return 2
    except OSError as error:
        print(
            f"Error reading '{target}': {error}",
            file=sys.stderr,
        )
        return 2

    print(format_report(result))

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\nJSON report saved to: {args.json_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
