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

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "indicators.json"
REQUIRED_INDICATOR_FIELDS = {"severity", "category", "message"}

CAPABILITY_MAP: dict[str, dict[str, str]] = {}
STRING_INDICATOR_MAP: dict[str, dict[str, str]] = {}


def load_indicator_config(
    config_path: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Load and validate configurable symbol and string indicators."""
    try:
        raw_config = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(
            f"Indicator configuration file was not found: {config_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Indicator configuration is not valid JSON: {error}"
        ) from error
    except OSError as error:
        raise ValueError(
            f"Could not read indicator configuration: {error}"
        ) from error

    if not isinstance(raw_config, dict):
        raise ValueError("Indicator configuration must contain a JSON object.")

    required_sections = ("symbol_indicators", "string_indicators")
    validated_sections: list[dict[str, dict[str, str]]] = []

    for section_name in required_sections:
        entries = raw_config.get(section_name)

        if not isinstance(entries, dict):
            raise ValueError(
                f"Configuration section '{section_name}' must be an object."
            )

        validated_entries: dict[str, dict[str, str]] = {}

        for marker, details in entries.items():
            if not isinstance(marker, str) or not marker:
                raise ValueError(
                    f"Configuration section '{section_name}' contains "
                    "an invalid indicator key."
                )

            if not isinstance(details, dict):
                raise ValueError(
                    f"Indicator '{marker}' in '{section_name}' must "
                    "contain an object."
                )

            missing_fields = REQUIRED_INDICATOR_FIELDS - set(details)

            if missing_fields:
                raise ValueError(
                    f"Indicator '{marker}' in '{section_name}' is missing: "
                    f"{', '.join(sorted(missing_fields))}"
                )

            normalized_details: dict[str, str] = {}

            for field in REQUIRED_INDICATOR_FIELDS:
                value = details[field]

                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"Indicator '{marker}' field '{field}' must "
                        "contain non-empty text."
                    )

                normalized_details[field] = value

            validated_entries[marker] = normalized_details

        validated_sections.append(validated_entries)

    return validated_sections[0], validated_sections[1]


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


def file_contains_marker(path: Path, marker: str) -> bool:
    """Check whether a byte marker appears in a file without loading it all."""
    marker_bytes = marker.encode("utf-8")
    overlap_size = max(len(marker_bytes) - 1, 0)
    trailing_bytes = b""

    with path.open("rb") as file_handle:
        while chunk := file_handle.read(CHUNK_SIZE):
            data = trailing_bytes + chunk

            if marker_bytes in data:
                return True

            trailing_bytes = (
                data[-overlap_size:] if overlap_size else b""
            )

    return False


def map_embedded_string_indicators(path: Path) -> list[dict[str, str]]:
    """Map selected embedded strings to cautious analyst-facing indicators."""
    indicators: list[dict[str, str]] = []

    for marker, details in STRING_INDICATOR_MAP.items():
        if not file_contains_marker(path, marker):
            continue

        indicators.append(
            {
                "severity": details["severity"],
                "category": details["category"],
                "string": marker,
                "message": details["message"],
            }
        )

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    return sorted(
        indicators,
        key=lambda item: (
            severity_order.get(item["severity"], 99),
            item["category"],
            item["string"],
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
        string_indicators = map_embedded_string_indicators(path)

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
            "embedded_string_indicators": string_indicators,
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

    string_indicators = result["embedded_string_indicators"]

    lines.extend(
        [
            "",
            "Embedded String Indicators:",
        ]
    )

    if not string_indicators:
        lines.append("  - No selected embedded-string indicators detected.")
    else:
        for indicator in string_indicators:
            lines.append(
                "  - "
                f"[{indicator['severity']}] "
                f"{indicator['category']} via string "
                f"{indicator['string']!r}: "
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
    parser.add_argument(
        "--config",
        dest="config_path",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=(
            "Path to the indicator configuration file. "
            f"Default: {DEFAULT_CONFIG_PATH}"
        ),
    )
    return parser.parse_args()


def main() -> int:
    """Run the ELF static inspection."""
    global CAPABILITY_MAP, STRING_INDICATOR_MAP

    args = parse_arguments()
    target = args.target

    if not target.is_file():
        print(
            f"Error: target file not found: {target}",
            file=sys.stderr,
        )
        return 2

    try:
        CAPABILITY_MAP, STRING_INDICATOR_MAP = load_indicator_config(
            args.config_path
        )
        result = analyze_elf(target)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
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
