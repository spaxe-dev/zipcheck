# Contributing

Thanks for helping make archive handling less exciting.

## Setup

```bash
git clone <this repository>
cd zipcheck
python -m pip install -e ".[dev]"
python -m pytest
ruff check src tests tools
mypy src/zipcheck
```

Python 3.10+ is required. Runtime code must stay dependency-free; if a feature
ever needs a third-party package, put it in an optional extra and make the
feature degrade gracefully when that extra is not installed.

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

## Fuzzing

Hypothesis property tests run with the normal suite. The coverage-guided
Atheris harness is Linux-only:

```bash
python -m pip install -e .[fuzz]
python fuzz/generate_seeds.py fuzz/corpus
python fuzz/fuzz_scan.py fuzz/corpus -max_total_time=120
```

The weekly `fuzz` workflow runs the same harness and uploads crashing inputs.

## Releasing

1. Bump `__version__` in `src/zipcheck/__init__.py`; the package version is read
   from that attribute. Add a `CHANGELOG.md` entry.
2. Run the full gate: `pytest`, `mypy src/zipcheck`, `ruff check src tests tools`,
   `python -m build` and `twine check dist/*`.
3. Commit, then tag and push `vX.Y.Z`. `.github/workflows/release.yml` builds and
   smoke-tests the sdist/wheel, publishes to PyPI through OIDC trusted
   publishing, and creates a GitHub release.
4. One-time setup: register a trusted publisher on PyPI for owner `spaxe-dev`,
   repository `zipcheck`, workflow `release.yml`, environment `pypi`; create the
   same `pypi` environment in the GitHub repository.
5. For AUR, wait for the GitHub release, update `pkgver` and checksums in
   `packaging/aur/PKGBUILD`, then run `updpkgsums` and
   `makepkg --printsrcinfo > .SRCINFO` before pushing to the AUR repository.

## Style

- `ruff check src tests tools` must pass.
- `mypy src/zipcheck` must pass.
- Line length 100.
- Type hints on public functions.
- Comments explain *why*, not *what*.

## Security

See [SECURITY.md](SECURITY.md) for how to report parser vulnerabilities
privately.
