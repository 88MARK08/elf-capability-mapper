# ELF Capability Mapper

## Static Linux Binary Analysis for Adversary-Tradecraft Indicators

ELF Capability Mapper is a defensive static-analysis tool for Linux ELF binaries. It reads an ELF file without executing it and produces an analyst-facing report that combines file metadata, dynamic imports, selected hardening signals, embedded-string indicators, and configurable capability mappings.

The tool does not determine whether a binary is malicious. Its purpose is to identify static features that may warrant closer review.

## Problem Definition

Analysts often need an initial view of an unfamiliar Linux executable before deciding whether deeper reverse engineering is necessary. Executing an unknown binary can introduce unnecessary risk, while low-level utilities may present information in separate, raw outputs that take time to interpret.

ELF Capability Mapper addresses this problem by collecting selected static facts from one ELF file and presenting them in a single terminal, JSON, or Markdown report. It focuses on features commonly relevant to reverse engineering and adversary-tradecraft analysis, including imports associated with process execution, anti-analysis, networking, dynamic loading, and memory-protection changes.

## Why This Matters

Linux ELF binaries are common in servers, containers, embedded systems, cloud workloads, and malware-analysis cases. A static first-pass review can help an analyst answer questions such as:

- What architecture and ELF type does the file use?
- Which shared libraries and dynamic imports does it expose?
- Does it contain imports associated with process execution, networking, debugger interaction, or memory-permission changes?
- Does it contain selected embedded strings that may be relevant to anti-analysis, dynamic loading, shell use, or retrieval tools?
- Which basic hardening-related signals are visible in the ELF metadata?

The resulting information is not a verdict. It helps determine where to focus subsequent analysis.

## Existing Approaches and Project Scope

Common ELF-analysis utilities include `readelf`, `objdump`, `nm`, `strings`, and `checksec`. Reverse-engineering frameworks such as Ghidra provide much deeper inspection, including disassembly and decompilation.

ELF Capability Mapper does not replace those tools. It provides a small, reproducible static-analysis workflow that combines selected data from several analysis areas into one configurable report:

- ELF metadata and dynamic linking information
- Dynamic-import capability indicators
- Selected embedded-string indicators
- Basic hardening-related signals
- JSON and Markdown output for review or automation

The project is intended as an initial triage aid and a teaching-oriented example of ELF parsing, not as a full malware classifier or reverse-engineering suite.

## Features

- Reads ELF files without executing them.
- Validates that the target is an ELF file before analysis.
- Reports file metadata, SHA-256, architecture, ELF type, entry point, interpreter, and needed shared libraries.
- Extracts undefined dynamic symbols from `.dynsym`.
- Maps selected imports to configurable capability indicators.
- Searches for selected embedded strings without loading the entire target into memory.
- Reports GNU RELRO presence, executable-stack marking, stack-canary import presence, and a PIE candidate signal.
- Produces terminal, JSON, and optional Markdown reports.
- Loads indicators from `config/indicators.json` so users can adjust mappings without editing Python code.
- Includes harmless source fixtures, a reproducible build script, regression tests, malformed-configuration checks, and GitHub Actions CI.

## Safety Model

ELF Capability Mapper performs static inspection only. It does not execute, emulate, unpack, or sandbox the target binary.

The sample fixtures are compiled locally for testing. The regression suite builds and scans them but does not run them. The capability fixture contains references to selected functions solely to create predictable dynamic imports for static analysis.

## Repository Structure

```text
elf-capability-mapper/
├── .github/
│   └── workflows/
│       └── elf-capability-mapper-ci.yml
├── config/
│   └── indicators.json
├── samples/
│   ├── bin/                         # Generated local binaries; not committed
│   └── source/
│       ├── hello.c
│       ├── capability_demo.c
│       └── string_indicator_demo.c
├── scripts/
│   └── build_samples.sh
├── src/
│   └── elf_capability_mapper.py
├── tests/
│   ├── fixtures/
│   │   └── invalid-indicators.json
│   ├── out/                         # Generated test reports; not committed
│   └── run_regression_tests.sh
├── results/                         # Generated reports; not committed
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements

The project was developed and tested on Kali Linux. To build the included fixtures, the system needs:

- Python 3
- `venv`
- `pip`
- GCC
- Bash

The scanner itself requires the Python dependency listed in `requirements.txt`:

```text
pyelftools
```

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/88MARK08/elf-capability-mapper.git
cd elf-capability-mapper
```

Create and activate a dedicated virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependency:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Confirm that the scanner can import `pyelftools`:

```bash
python -c "from elftools.elf.elffile import ELFFile; print('pyelftools ready')"
```

## Build the Included Test Fixtures

The project includes three harmless source fixtures. Build them locally with:

```bash
scripts/build_samples.sh
```

The script creates these files under `samples/bin/`:

- `hello`: a safe baseline fixture with no selected indicators.
- `capability_demo`: a fixture that exposes selected import-based capability indicators.
- `string_indicator_demo`: a fixture that contains selected embedded-string indicators.

## Basic Usage

Display help:

```bash
python src/elf_capability_mapper.py --help
```

Scan an ELF file and print a terminal report:

```bash
python src/elf_capability_mapper.py /path/to/target
```

For example, after building the fixtures:

```bash
python src/elf_capability_mapper.py samples/bin/hello
```

## JSON and Markdown Reports

Write a JSON report:

```bash
python src/elf_capability_mapper.py \
  samples/bin/capability_demo \
  --json results/capability-demo.json
```

Write both JSON and Markdown reports:

```bash
python src/elf_capability_mapper.py \
  samples/bin/capability_demo \
  --json results/capability-demo.json \
  --markdown results/capability-demo.md
```

Inspect a JSON report with Python:

```bash
python -m json.tool results/capability-demo.json
```

The Markdown report includes:

- File metadata
- Needed shared libraries
- Hardening signals
- Analyst summary
- Import-based capability indicators
- Embedded-string indicators

## What the Scanner Reports

### File Metadata

The scanner reports:

- File path
- SHA-256 hash
- File size
- ELF class
- Endianness
- Architecture
- ELF type
- Entry point
- ELF interpreter, when present
- Needed shared libraries

### Dynamic Imports

The tool reads undefined symbols from the dynamic symbol table (`.dynsym`). Imports are preserved in JSON output, while selected imports are mapped to capability indicators in the terminal and Markdown reports.

### Import-Based Capability Indicators

The default configuration includes these indicator groups:

| Category | Default Symbols | Severity |
|---|---|---|
| Anti-analysis | `ptrace` | MEDIUM |
| Command execution | `system`, `popen` | MEDIUM |
| Process execution | `execve`, `execl`, `execvp` | MEDIUM |
| Dynamic loading | `dlopen`, `dlsym` | LOW |
| Networking | `socket`, `connect`, `send`, `recv` | LOW |
| Memory protection | `mprotect` | MEDIUM |

A symbol import indicates that the binary may expose that capability. It does not show whether a specific code path invokes the capability.

### Embedded-String Indicators

The default configuration checks for the following strings:

| String | Category | Severity |
|---|---|---|
| `/proc/self/status` | Anti-analysis | MEDIUM |
| `LD_PRELOAD` | Dynamic loading | MEDIUM |
| `/bin/sh` | Command execution | MEDIUM |
| `curl` | Retrieval tool | LOW |
| `wget` | Retrieval tool | LOW |

A matching string may occur in benign software, documentation, error messages, or unused code. It should be evaluated in context.

### Hardening Signals

The report includes these basic ELF signals:

| Signal | Interpretation |
|---|---|
| GNU RELRO segment | Whether a `PT_GNU_RELRO` program-header segment is present. |
| Stack marking | Whether `PT_GNU_STACK` is present and requests executable or non-executable stack permissions. |
| Stack canary import | Whether `__stack_chk_fail` appears in dynamic imports. |
| PIE candidate | Whether the file is `ET_DYN` and has an ELF interpreter. |

These fields are signals, not a complete hardening assessment. In particular, GNU RELRO segment presence does not distinguish partial from full RELRO, and the PIE field is a candidate status rather than an exhaustive determination.

## Analyst Summary

Each report includes a summary that counts selected import-based and embedded-string indicators by severity. The summary is intentionally not a malware score.

For the included `capability_demo` fixture, the expected summary is:

```text
Import-based indicators: 10
Embedded-string indicators: 0
Total selected indicators: 10
Severity counts: HIGH 0 | MEDIUM 4 | LOW 6
```

The report also states that static indicators require analyst review and context.

## Configurable Indicators

Default indicator definitions are stored in:

```text
config/indicators.json
```

The file contains two top-level sections:

- `symbol_indicators`: mappings for dynamic imports.
- `string_indicators`: mappings for embedded strings.

Each indicator must contain `severity`, `category`, and `message` fields. Example:

```json
{
  "puts": {
    "severity": "LOW",
    "category": "output",
    "message": "Console-output capability may be present."
  }
}
```

Use an alternate configuration without changing the scanner source:

```bash
python src/elf_capability_mapper.py \
  samples/bin/hello \
  --config /path/to/custom-indicators.json
```

The tool validates the configuration before scanning. Invalid JSON, missing required sections, or incomplete indicator entries produce an error and exit code `2`.

## Testing

Run the full regression suite:

```bash
./tests/run_regression_tests.sh
```

The suite performs the following checks:

- Builds the three local sample binaries.
- Confirms `hello` has zero selected import and string indicators.
- Confirms `capability_demo` has ten expected import-based indicators.
- Confirms `string_indicator_demo` has five expected embedded-string indicators.
- Checks expected hardening signals for all three fixtures.
- Confirms the analyst-summary values match expected results.
- Generates and checks a Markdown report.
- Confirms a non-ELF input is rejected with exit code `2`.
- Confirms an invalid indicator configuration is rejected with exit code `2`.

A successful run ends with:

```text
Regression test passed.
```

## Continuous Integration

GitHub Actions runs the regression suite on pushes and pull requests targeting `main`.

The workflow file is:

```text
.github/workflows/elf-capability-mapper-ci.yml
```

The workflow:

1. Checks out the repository.
2. Sets up Python 3.13.
3. Installs dependencies from `requirements.txt`.
4. Compiles the scanner with `py_compile`.
5. Runs `./tests/run_regression_tests.sh`.

## Example Demonstration Sequence

Use the following commands for a local demonstration:

```bash
source .venv/bin/activate
scripts/build_samples.sh

python src/elf_capability_mapper.py \
  samples/bin/hello \
  --json results/hello.json \
  --markdown results/hello.md

python src/elf_capability_mapper.py \
  samples/bin/capability_demo \
  --json results/capability-demo.json \
  --markdown results/capability-demo.md

python src/elf_capability_mapper.py \
  samples/bin/string_indicator_demo \
  --json results/string-demo.json \
  --markdown results/string-demo.md

./tests/run_regression_tests.sh
```

Expected observations:

- `hello` has no selected capability or embedded-string indicators.
- `capability_demo` produces ten import-based indicators.
- `string_indicator_demo` produces five embedded-string indicators.
- The regression suite confirms expected behavior.

## Limitations

- The tool performs static inspection only and does not observe runtime behavior.
- Import presence does not prove a function is called during execution.
- Statically linked binaries, direct system calls, stripped binaries, packed binaries, and custom loaders may reduce or change available signals.
- Embedded-string matches can be benign or unrelated to reachable code.
- The scanner does not unpack binaries, disassemble instructions, trace data flow, resolve indirect calls, or decompile functions.
- The scanner does not identify vulnerabilities, scan packages, assign CVEs, or determine whether a file is malicious.
- The current hardening output is intentionally limited and should not replace a dedicated hardening-analysis utility.
- The included fixtures are designed for controlled testing and do not represent real malware.

## Future Work

Possible extensions include:

- Batch scanning of directories and recursive ELF discovery.
- CSV or SARIF output for integration with other tooling.
- Additional hardening signals and architecture-specific checks.
- Optional MITRE ATT&CK annotations for selected indicators.
- Optional YARA integration for content-based detection.
- Rule profiles and severity filters.
- Comparison against larger, benign open-source ELF collections to tune indicator mappings.
- Integration points for external tools such as `checksec`, disassemblers, or sandbox reports.

## Declaration of Generative AI Usage

ChatGPT was used during development for grammar refinement, documentation editing, and the creation of synthetic test examples. All generated material was reviewed, revised, and validated by the author. The author is responsible for the final design, implementation, testing, and submission.

## Author

Markjoe Uba
