#!/usr/bin/env python3
"""
ELF Capability Mapper

Static Linux ELF analysis for analyst-facing capability indicators.
The tool reads ELF files without executing them.
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
STRING_INDICATOR_MAP: dict[str, dict[str, Any]] = {}


def load_indicator_config(
    config_path: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]]]:
    """Load and validate symbol and string indicator configuration."""
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

    symbol_entries = raw_config.get("symbol_indicators")
    string_entries = raw_config.get("string_indicators")

    if not isinstance(symbol_entries, dict):
        raise ValueError(
            "Configuration section 'symbol_indicators' must be an object."
        )

    if not isinstance(string_entries, dict):
        raise ValueError(
            "Configuration section 'string_indicators' must be an object."
        )

    validated_symbols = validate_indicator_section(
        symbol_entries,
        "symbol_indicators",
        allow_case_sensitive=False,
    )

    validated_strings = validate_indicator_section(
        string_entries,
        "string_indicators",
        allow_case_sensitive=True,
    )

    return validated_symbols, validated_strings


def validate_indicator_section(
    entries: dict[str, Any],
    section_name: str,
    allow_case_sensitive: bool,
) -> dict[str, dict[str, Any]]:
    """Validate one configuration section."""
    validated_entries: dict[str, dict[str, Any]] = {}

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

        normalized_details: dict[str, Any] = {}

        for field in REQUIRED_INDICATOR_FIELDS:
            value = details[field]

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Indicator '{marker}' field '{field}' must "
                    "contain non-empty text."
                )

            normalized_details[field] = value

        if allow_case_sensitive:
            case_sensitive = details.get("case_sensitive", True)

            if not isinstance(case_sensitive, bool):
                raise ValueError(
                    f"Indicator '{marker}' field 'case_sensitive' must "
                    "be true or false."
                )

            normalized_details["case_sensitive"] = case_sensitive

        validated_entries[marker] = normalized_details

    return validated_entries


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
    """Map selected imports to analyst-facing capability indicators."""
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


def find_all_offsets(data: bytes, pattern: bytes) -> list[int]:
    """Return every offset of pattern within data."""
    offsets: list[int] = []
    start = 0

    while True:
        index = data.find(pattern, start)

        if index == -1:
            break

        offsets.append(index)
        start = index + 1

    return offsets


def map_embedded_string_indicators(path: Path) -> list[dict[str, Any]]:
    """Find configured embedded strings in one file-read pass."""
    if not STRING_INDICATOR_MAP:
        return []

    prepared_markers: list[dict[str, Any]] = []

    for marker, details in STRING_INDICATOR_MAP.items():
        marker_bytes = marker.encode("utf-8")
        case_sensitive = bool(details.get("case_sensitive", True))

        prepared_markers.append(
            {
                "marker": marker,
                "marker_bytes": marker_bytes,
                "search_bytes": (
                    marker_bytes if case_sensitive else marker_bytes.lower()
                ),
                "case_sensitive": case_sensitive,
                "details": details,
                "offsets": set(),
            }
        )

    max_marker_length = max(
        len(item["marker_bytes"]) for item in prepared_markers
    )
    overlap_size = max_marker_length - 1
    trailing_bytes = b""
    bytes_read = 0

    with path.open("rb") as file_handle:
        while chunk := file_handle.read(CHUNK_SIZE):
            data = trailing_bytes + chunk
            data_start_offset = bytes_read - len(trailing_bytes)
            bytes_read += len(chunk)

            for item in prepared_markers:
                case_sensitive = item["case_sensitive"]
                search_data = data if case_sensitive else data.lower()

                for relative_offset in find_all_offsets(
                    search_data,
                    item["search_bytes"],
                ):
                    absolute_offset = data_start_offset + relative_offset

                    if absolute_offset >= 0:
                        item["offsets"].add(absolute_offset)

            trailing_bytes = data[-overlap_size:] if overlap_size else b""

    indicators: list[dict[str, Any]] = []

    for item in prepared_markers:
        offsets = sorted(item["offsets"])

        if not offsets:
            continue

        details = item["details"]

        indicators.append(
            {
                "severity": details["severity"],
                "category": details["category"],
                "string": item["marker"],
                "message": details["message"],
                "case_sensitive": item["case_sensitive"],
                "file_offsets": [f"0x{offset:x}" for offset in offsets],
                "match_count": len(offsets),
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


def build_analysis_summary(
    capability_indicators: list[dict[str, str]],
    string_indicators: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return counts that help an analyst review selected indicators."""
    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for indicator in capability_indicators + string_indicators:
        severity = indicator["severity"]

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "import_indicator_count": len(capability_indicators),
        "embedded_string_indicator_count": len(string_indicators),
        "total_indicator_count": (
            len(capability_indicators) + len(string_indicators)
        ),
        "severity_counts": severity_counts,
    }


def get_hardening_signals(
    elf: ELFFile,
    imports: list[str],
    interpreter: str | None,
) -> dict[str, Any]:
    """Collect hardening-related signals from ELF metadata."""
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


def analyze_elf(path: Path, config_path: Path) -> dict[str, Any]:
    """Collect static ELF metadata, imports, indicators, and hardening."""
    file_size = path.stat().st_size
    file_hash = calculate_sha256(path)

    with path.open("rb") as file_handle:
        elf = ELFFile(file_handle)
        interpreter = get_interpreter(elf)
        imports = get_dynamic_imports(elf)
        capability_indicators = map_capability_indicators(imports)
        string_indicators = map_embedded_string_indicators(path)
        analysis_summary = build_analysis_summary(
            capability_indicators,
            string_indicators,
        )

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
            "capability_indicators": capability_indicators,
            "embedded_string_indicators": string_indicators,
            "analysis_summary": analysis_summary,
            "hardening": get_hardening_signals(
                elf,
                imports,
                interpreter,
            ),
            "configuration": {
                "path": str(config_path),
                "symbol_indicator_count": len(CAPABILITY_MAP),
                "string_indicator_count": len(STRING_INDICATOR_MAP),
            },
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
    summary = result["analysis_summary"]

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
            "Analyst Summary:",
            (
                "  - Import-based indicators: "
                f"{summary['import_indicator_count']}"
            ),
            (
                "  - Embedded-string indicators: "
                f"{summary['embedded_string_indicator_count']}"
            ),
            (
                "  - Total selected indicators: "
                f"{summary['total_indicator_count']}"
            ),
            (
                "  - Severity counts: "
                f"HIGH {summary['severity_counts']['HIGH']} | "
                f"MEDIUM {summary['severity_counts']['MEDIUM']} | "
                f"LOW {summary['severity_counts']['LOW']}"
            ),
            "  - Note: Static indicators require analyst review and context.",
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

    lines.extend(["", "Embedded String Indicators:"])

    if not string_indicators:
        lines.append("  - No selected embedded-string indicators detected.")
    else:
        for indicator in string_indicators:
            offsets = ", ".join(indicator["file_offsets"])
            case_text = (
                "case-sensitive"
                if indicator["case_sensitive"]
                else "case-insensitive"
            )
            lines.append(
                "  - "
                f"[{indicator['severity']}] "
                f"{indicator['category']} via string "
                f"{indicator['string']!r}: "
                f"{indicator['message']} "
                f"(matches: {indicator['match_count']}; "
                f"offsets: {offsets}; {case_text})"
            )

    return "\n".join(lines)


def format_verbose_report(result: dict[str, Any]) -> str:
    """Format optional verbose scan details."""
    config = result["configuration"]

    lines = [
        "Verbose Scan Details",
        "=" * 48,
        f"Configuration file: {config['path']}",
        f"Symbol indicators loaded: {config['symbol_indicator_count']}",
        f"String indicators loaded: {config['string_indicator_count']}",
        f"Dynamic imports scanned: {result['import_count']}",
        (
            "Capability indicators matched: "
            f"{len(result['capability_indicators'])}"
        ),
        (
            "Embedded-string indicators matched: "
            f"{len(result['embedded_string_indicators'])}"
        ),
        "",
        "Matched imported symbols:",
    ]

    if result["capability_indicators"]:
        for indicator in result["capability_indicators"]:
            lines.append(
                f"  - {indicator['symbol']} "
                f"({indicator['category']}, {indicator['severity']})"
            )
    else:
        lines.append("  - None")

    lines.append("")
    lines.append("Matched embedded strings:")

    if result["embedded_string_indicators"]:
        for indicator in result["embedded_string_indicators"]:
            offsets = ", ".join(indicator["file_offsets"])
            lines.append(
                f"  - {indicator['string']!r} "
                f"({indicator['category']}, {indicator['severity']}) "
                f"at {offsets}"
            )
    else:
        lines.append("  - None")

    return "\n".join(lines)


def format_markdown_report(result: dict[str, Any]) -> str:
    """Format static-analysis results as a Markdown report."""
    hardening = result["hardening"]
    summary = result["analysis_summary"]

    lines = [
        "# ELF Capability Mapper Report",
        "",
        "## File Metadata",
        "",
        f"- **File:** `{result['file']}`",
        f"- **SHA-256:** `{result['sha256']}`",
        f"- **Size:** {result['size_bytes']} bytes",
        f"- **ELF Class:** {result['elf_class']}",
        f"- **Endianness:** {result['endianness']}",
        f"- **Architecture:** {result['architecture']}",
        f"- **ELF Type:** {result['elf_type']}",
        f"- **Entry Point:** `{result['entry_point']}`",
        (
            f"- **Interpreter:** `{result['interpreter']}`"
            if result["interpreter"]
            else "- **Interpreter:** None detected"
        ),
        "",
        "## Needed Shared Libraries",
        "",
    ]

    libraries = result["needed_libraries"]

    if libraries:
        lines.extend(f"- `{library}`" for library in libraries)
    else:
        lines.append("- None detected")

    lines.extend(
        [
            "",
            "## Hardening Signals",
            "",
            (
                "- **GNU RELRO segment:** "
                + (
                    "Present"
                    if hardening["gnu_relro_segment"]
                    else "Not detected"
                )
            ),
            (
                "- **Executable stack:** "
                + (
                    "Yes — review recommended"
                    if hardening["executable_stack"] is True
                    else (
                        "No"
                        if hardening["executable_stack"] is False
                        else "Not specified"
                    )
                )
            ),
            (
                "- **Stack canary import:** "
                + (
                    "Present"
                    if hardening["stack_canary_import"]
                    else "Not detected"
                )
            ),
            (
                "- **PIE candidate:** "
                + ("Yes" if hardening["pie_candidate"] else "No")
            ),
            "",
            "## Analyst Summary",
            "",
            (
                "- **Import-based indicators:** "
                f"{summary['import_indicator_count']}"
            ),
            (
                "- **Embedded-string indicators:** "
                f"{summary['embedded_string_indicator_count']}"
            ),
            (
                "- **Total selected indicators:** "
                f"{summary['total_indicator_count']}"
            ),
            (
                "- **Severity counts:** "
                f"HIGH {summary['severity_counts']['HIGH']} | "
                f"MEDIUM {summary['severity_counts']['MEDIUM']} | "
                f"LOW {summary['severity_counts']['LOW']}"
            ),
            "",
            "Static indicators require analyst review and context. "
            "They do not establish that a binary is malicious.",
            "",
            "## Import-Based Capability Indicators",
            "",
        ]
    )

    capability_indicators = result["capability_indicators"]

    if not capability_indicators:
        lines.append("- No selected capability indicators detected.")
    else:
        for indicator in capability_indicators:
            lines.append(
                f"- **[{indicator['severity']}] "
                f"{indicator['category']} via "
                f"`{indicator['symbol']}`:** "
                f"{indicator['message']}"
            )

    lines.extend(["", "## Embedded String Indicators", ""])

    string_indicators = result["embedded_string_indicators"]

    if not string_indicators:
        lines.append("- No selected embedded-string indicators detected.")
    else:
        for indicator in string_indicators:
            offsets = ", ".join(f"`{x}`" for x in indicator["file_offsets"])
            lines.append(
                f"- **[{indicator['severity']}] "
                f"{indicator['category']} via string "
                f"`{indicator['string']}`:** "
                f"{indicator['message']} "
                f"Match count: {indicator['match_count']}. "
                f"File offsets: {offsets}."
            )

    return "\n".join(lines) + "\n"


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
    parser.add_argument(
        "--markdown",
        dest="markdown_output",
        type=Path,
        help="Optional path for a Markdown report.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show additional details about configuration and matches.",
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
        result = analyze_elf(target, args.config_path)
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

    if args.verbose:
        print("")
        print(format_verbose_report(result))

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\nJSON report saved to: {args.json_output}")

    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(
            format_markdown_report(result),
            encoding="utf-8",
        )
        print(f"Markdown report saved to: {args.markdown_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
