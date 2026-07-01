# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release scaffolding.
- Read-only `MsgContainer` over `olefile` with FAT / mini-FAT byte-offset mapping.
- Seven detectors: `ORPHAN_SUBSTG`, `HEADER_COUNTS`, `MSGFLAGS`,
  `FILETIME_SANITY`, `NAMEID_INTEGRITY`, `ATTACH_OLEGUID`, `CODEPAGE_MISMATCH`.
- Deterministic JSON report and human-readable terminal report (no verdict/score).
- `msgscope inspect` CLI with `--format`, `--fail-on`, `--reproducible`,
  `--checks`/`--exclude`, `--list-checks`.
- Pluggable check discovery via the `msgscope.checks` entry-point group.
- In-repo CFB writer and message builders for byte-precise fixtures; full test
  suite asserting each detector fires only where expected.
