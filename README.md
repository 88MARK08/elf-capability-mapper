# ELF Capability Mapper

ELF Capability Mapper is a defensive static-analysis tool for Linux ELF binaries.

It reads an ELF file without executing it and reports metadata, imported symbols,
linked libraries, selected hardening signals, embedded strings, and potentially
security-relevant capabilities.

The tool does not determine whether a file is malicious. It helps an analyst
identify features that may warrant closer review.
