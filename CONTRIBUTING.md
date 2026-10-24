# Contributing

Thanks for helping make archive handling less exciting.

## Setup

```bash
git clone <this repository>
cd zipcheck
python -m pip install -e .[dev]
python -m pytest
ruff check src tests tools
```

Python 3.9+ is required. Runtime code must stay dependency-free; optional
extras (for example `zstandard`) belong in `pyproject.toml` under an extra and
must degrade gracefully when absent.

## Ground rules

1. **Never extract member data.** Parsers may read metadata, and may decompress
   a *bounded* prefix into memory for nested-archive inspection. They must
   never write extracted content to disk, emit temp files, or call external
   archive tools.
2. **Never allocate from a declared size.** A header claiming 10 TiB must not
   cause a 10 TiB allocation. Read in fixed-size chunks and stop at a cap.
3. **Fail closed.** If metadata cannot be read reliably, the result must be
   `unknown` — not `clean`.
4. **No exceptions escape `scan_file`.** Malformed input is normal input.
5. **Add a test for every parser change.** Prefer a metadata-only fixture (a
   few dozen bytes) over a real bomb.
6. **Keep the output stable.** JSON field names are part of the public API.

## Adding a format

1. Add magic/extension routing in `detect.py`.
2. Add a parser module under `src/zipcheck/formats/` exposing
   `scan(fp, size, limits, deadline) -> Facts`.
3. Read sizes from headers or indexes. If the format has no size field, use
   `formats/probe.py` with a bounded output and explain the limitation in the
   module docstring.
4. Register it in `engine.PARSERS` and decide whether nested inspection is
   feasible.
5. Add tests: a clean sample, a declared-huge sample, and a malformed sample.
6. Document where the size lives in `docs/metadata-map.md` and add the format to
   the README table.

## Adding a detection rule

- Emit a `Finding` with a stable `code`, a severity, and a human explanation.
- Policy thresholds belong in `Limits`, not hard-coded in a parser.
- Keep false positives explainable: "this is a large expansion", not "this is
  malware".
- Update the rules table in `README.md`.

## Test fixtures

Use `tests/helpers.py` to build archives. Tests must not contain or download
live bombs. If a real archive is essential to reproduce a bug, minimise it to a
metadata-only file first.

For integration testing against real bombs, use `tools/generate_samples.py`
inside a disposable VM/container. The generated files are small on disk but
enormous when extracted.

## Style

- `ruff check src tests tools` must pass.
- Line length 100.
- Type hints on public functions.
- Comments explain *why*, not *what*.

## Security

See [SECURITY.md](SECURITY.md) for how to report parser vulnerabilities
privately.
