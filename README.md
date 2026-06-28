# ELF Capability Mapper

ELF Capability Mapper is a defensive static-analysis tool for Linux ELF binaries.

It reads an ELF file without executing it and reports metadata, imported symbols,
linked libraries, selected hardening signals, embedded strings, and potentially
security-relevant capabilities.

The tool does not determine whether a file is malicious. It helps an analyst
identify features that may warrant closer review.

## Configurable Indicators

Default import-based and embedded-string indicators are stored in:

```text
config/indicators.json
```

The configuration has two sections:

- `symbol_indicators`: imported ELF symbols such as `ptrace`, `system`, `execve`, `socket`, and `mprotect`.
- `string_indicators`: embedded strings such as `/proc/self/status`, `LD_PRELOAD`, `/bin/sh`, `curl`, and `wget`.

Each indicator requires:

```json
{
  "severity": "LOW, MEDIUM, or HIGH",
  "category": "analyst-facing category",
  "message": "explanation of why the feature may merit review"
}
```

Use a custom configuration without editing Python code:

```bash
python src/elf_capability_mapper.py \
  samples/bin/hello \
  --config /path/to/custom-indicators.json
```

The tool validates the configuration before scanning. Invalid JSON, missing configuration sections, or incomplete indicator entries produce an error and exit code `2`.
