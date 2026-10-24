# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-24

First public release.

### Added

- Static metadata scanners for ZIP/ZIP64, TAR (including GNU/PAX sparse),
  gzip, bzip2, xz/LZMA, Zstandard, 7-Zip and RAR 4/5.
- Expansion-ratio and absolute-size policy with `clean` / `suspicious` /
  `dangerous` / `unknown` verdicts.
- Detection of impossible DEFLATE ratios, stored-size mismatches, overlapping
  entries, shared local headers and inconsistent totals.
- Bounded nested-archive inspection (ZIP, TAR, gzip, bzip2, xz) with depth,
  archive-count, byte and time budgets.
- Bounded in-memory decompression probe for formats without declared sizes.
- Bounded content verification (`--verify`, `--verify-limit`,
  `--require-verified`) that decompresses supported content into an in-memory
  counting sink, never to disk.
- `--production` fail-closed preset for user-upload pipelines; it implies
  `--verify --require-verified`.
- Recursive verification of nested archives: images up to 8 MiB are captured
  and scanned with a shared 256 MiB nested-output budget.
- New integrity findings: `HEADER_MISMATCH`, `ENTRY_COUNT_MISMATCH`,
  `UNDERSTATED_COMPRESSED_SIZE`, `OVERSTATED_COMPRESSED_SIZE`,
  `VERIFICATION_FAILED` and `UNVERIFIED`.
- `nested_unverified` in JSON output, propagated from child scans to the parent.
- CLI with human and JSON output, directory recursion, configurable fail
  thresholds and documented exit codes.
- PEP 517/621 packaging with a typed-package marker, wheel/sdist smoke tests,
  and PyPI trusted publishing through GitHub OIDC.
- CI across Linux, macOS and Windows on Python 3.10-3.14, with branch coverage,
  ruff and mypy gates.
- Hypothesis property tests and a coverage-guided Atheris fuzz harness with a
  seed corpus and a weekly fuzz workflow.
- Arch Linux AUR packaging under `packaging/aur`.
- Safe test corpus generators, sandbox benchmark tool, Dockerfile, and
  documentation of where each format stores its uncompressed size and why a
  magic "bomb signature" does not exist.

### Fixed

- The ZIP parser now parses the central directory to its declared end instead of
  stopping at the attacker-controlled EOCD entry count, exposing hidden entries.
- Local headers are cross-checked against central-directory metadata, so tools
  cannot be played against each other with contradictory sizes or methods.
- Verification detects compressed streams that continue past their declared
  `csize`, catching forged one-byte members.
- xz content verification drained the decoder's buffered output correctly;
  highly compressible streams were previously under-measured and reported as
  `METADATA_OVERSTATED` instead of being fully verified.
- Verification failures and unverifiable nested content now fail closed
  (`suspicious`, or `unknown` under `--require-verified`) instead of reporting
  `clean`.
- Nested gzip inspection now follows concatenated members instead of stopping at
  the first one, so an archive split across members is still inspected.
- Nested xz and bzip2 prefix capture now drains the decoders' buffered output,
  so a highly compressible inner archive is captured completely.
- ZIP LZMA members are now decoded for nested-archive sniffing (bounded), not
  skipped silently.
- Hitting the central-directory parse limit is reported as truncation
  (`MEDIUM`) instead of being misclassified as hidden entries (`HIGH`).
- A malformed-header unpack in the nested ZIP prefix parser shifted `csize` and
  `usize` by two bytes; fixed.
- `scan_file` now opens the file before `fstat`ing the same descriptor,
  removing a stat-then-open race.
- Human-readable output now groups repeated nested siblings correctly instead of
  printing each one at the same indentation.

[0.1.0]: https://github.com/spaxe-dev/zipcheck/releases/tag/v0.1.0
