# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-24

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
- CLI with human and JSON output, directory recursion, configurable fail
  thresholds and documented exit codes.
- Safe test corpus generators, sandbox benchmark tool, CI workflow, Dockerfile.
- Documentation of where each format stores its uncompressed size and why a
  magic "bomb signature" does not exist.
