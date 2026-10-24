"""Command-line interface for zipcheck."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .detect import extension_suggests_archive
from .engine import scan_file
from .limits import Limits
from .model import ScanResult, Severity
from .reader import human_ratio, human_size

VERDICT_COLORS = {
    "clean": "\x1b[32m",
    "suspicious": "\x1b[33m",
    "dangerous": "\x1b[31m",
    "unknown": "\x1b[90m",
}
SEVERITY_COLORS = {
    Severity.INFO: "\x1b[90m",
    Severity.LOW: "\x1b[36m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.HIGH: "\x1b[31m",
    Severity.CRITICAL: "\x1b[1;31m",
}
RESET = "\x1b[0m"


def _parse_size(value: str) -> int:
    text = value.strip().lower().replace("_", "")
    if not text:
        raise argparse.ArgumentTypeError("empty size")
    suffixes = {
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "tib": 1024**4,
    }
    for suffix in sorted(suffixes, key=len, reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)].strip()
            try:
                return int(float(number) * suffixes[suffix])
            except ValueError as exc:
                raise argparse.ArgumentTypeError(f"invalid size: {value}") from exc
    try:
        return int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid size: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zipcheck",
        description=(
            "Static zip-bomb / archive-bomb detector. Reads only archive metadata; "
            "it never extracts files and never writes member data."
        ),
        epilog=(
            "Exit codes: 0 clean (or below --fail-on), 1 suspicious, 2 dangerous, "
            "3 unknown/unscannable, 4 invocation or I/O error."
        ),
    )
    parser.add_argument("paths", nargs="+", metavar="PATH", help="archive file(s) to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="recurse into directories")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--fail-on",
        choices=("none", "suspicious", "dangerous"),
        default="suspicious",
        help="lowest verdict that causes a non-zero exit (default: suspicious)",
    )
    parser.add_argument("--depth", type=int, default=6, help="maximum nested archive depth")
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="per-file wall-clock limit in seconds"
    )
    parser.add_argument(
        "--no-probe",
        dest="probe",
        action="store_false",
        help=(
            "do not run bounded decompression for gzip, bzip2, size-less "
            "formats or ZIP stream-tail consistency checks"
        ),
    )
    parser.add_argument(
        "--probe-limit",
        type=_parse_size,
        default=64 * 1024 * 1024,
        help=(
            "maximum bytes produced by a bounded probe per file "
            "(default: 64MiB; applies to gzip and size-less formats)"
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="decompress content into a counting sink to detect forged metadata",
    )
    parser.add_argument(
        "--verify-limit",
        type=_parse_size,
        default=512 * 1024 * 1024,
        help="maximum bytes produced by content verification (default: 512MiB)",
    )
    parser.add_argument(
        "--require-verified",
        action="store_true",
        help="fail closed (unknown) when content cannot be verified; implies --verify",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help=(
            "fail-closed preset for user uploads: verify content and reject "
            "archives that cannot be fully verified (implies --verify "
            "--require-verified)"
        ),
    )
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument(
        "--password",
        metavar="TEXT",
        help=(
            "password for encrypted ZIP members (visible in shell history and "
            "the process list; prefer --ask-password or --password-file)"
        ),
    )
    password_group.add_argument(
        "--password-file",
        metavar="PATH",
        help="read the ZIP password from the first line of a file",
    )
    password_group.add_argument(
        "--ask-password",
        action="store_true",
        help="prompt for the ZIP password on the terminal",
    )
    parser.add_argument(
        "--ratio",
        type=float,
        default=100.0,
        help="expansion ratio considered suspicious (default: 100)",
    )
    parser.add_argument(
        "--dangerous-ratio",
        type=float,
        default=1000.0,
        help="expansion ratio considered dangerous (default: 1000)",
    )
    parser.add_argument(
        "--min-size",
        type=_parse_size,
        default=16 * 1024 * 1024,
        help="ignore expansion ratios below this declared size (default: 16MiB)",
    )
    parser.add_argument(
        "--entries",
        type=int,
        default=10,
        help="number of archive members to show in human output (default: 10)",
    )
    parser.add_argument("--quiet", action="store_true", help="one line per file")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show notes and member samples"
    )
    parser.add_argument("--version", action="version", version=f"zipcheck {__version__}")
    return parser


def _resolve_password(args: argparse.Namespace) -> Tuple[Optional[bytes], Optional[int]]:
    """Return ``(password, exit_code)``; one of them is always None."""

    if args.password is not None:
        value = args.password.encode("utf-8")
        if not value:
            print("zipcheck: --password must not be empty", file=sys.stderr)
            return None, 4
        return value, None
    if args.password_file is not None:
        try:
            with open(args.password_file, "rb") as handle:
                value = handle.readline().rstrip(b"\r\n")
        except OSError as exc:
            print(f"zipcheck: cannot read password file: {exc}", file=sys.stderr)
            return None, 4
        if not value:
            print("zipcheck: password file is empty", file=sys.stderr)
            return None, 4
        return value, None
    if args.ask_password:
        try:
            value = getpass.getpass("Archive password: ").encode("utf-8")
        except (EOFError, KeyboardInterrupt):
            print("zipcheck: no password entered", file=sys.stderr)
            return None, 4
        return (value or None), None
    return None, None


def _collect_paths(paths: Sequence[str], recursive: bool) -> List[str]:
    collected: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            if not recursive:
                raise IsADirectoryError(
                    f"{path!r} is a directory (use --recursive to scan its archives)"
                )
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for name in sorted(files):
                    candidate = os.path.join(root, name)
                    if extension_suggests_archive(candidate):
                        collected.append(candidate)
        else:
            collected.append(path)
    return collected


def _colorize(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def _print_result(result: ScanResult, args: argparse.Namespace, color: bool) -> None:
    indent = "  " * (result.depth + 1)
    verdict = result.verdict.upper()
    colored_verdict = _colorize(verdict, VERDICT_COLORS.get(result.verdict, ""), color)
    print(f"{indent}{colored_verdict}  {result.path}")
    print(f"{indent}  format:    {result.format} ({result.detail or 'n/a'})")
    print(f"{indent}  on disk:   {human_size(result.size)}")
    if result.declared_uncompressed is not None:
        ratio = result.ratio
        print(
            f"{indent}  declared:  {human_size(result.declared_uncompressed)}"
            f"  ({human_ratio(ratio)})"
        )
    if result.entry_count is not None:
        print(f"{indent}  members:   {result.entry_count:,}")
    if result.verified is not None:
        state = "verified" if result.verified else "unverified"
        if result.verification_capped:
            state += " (cap reached)"
        print(
            f"{indent}  verify:    {state}, "
            f"{human_size(result.verified_uncompressed)} produced - {result.verification_detail}"
        )
    if result.error:
        print(f"{indent}  error:     {result.error}")

    for finding in result.findings:
        color_code = SEVERITY_COLORS.get(finding.severity, "")
        severity = _colorize(finding.severity.label.upper(), color_code, color)
        print(f"{indent}  [{severity}] {finding.code}: {finding.title}")
        if args.verbose or finding.severity >= Severity.MEDIUM:
            print(f"{indent}          {finding.detail}")

    if args.verbose and result.notes:
        for note in result.notes:
            print(f"{indent}  note: {note}")

    if args.verbose and result.entries:
        print(f"{indent}  members (sample):")
        for entry in result.entries[: args.entries]:
            kind = "dir" if entry.is_dir else entry.method or "?"
            print(
                f"{indent}    {entry.name!r}  {human_size(entry.usize)}  "
                f"({kind}, {human_ratio(entry.ratio)})"
            )

    for index, child in enumerate(result.nested):
        if args.verbose or index == 0:
            _print_result(child, args, color)
        else:
            child_verdict = _colorize(
                child.verdict.upper(), VERDICT_COLORS.get(child.verdict, ""), color
            )
            print(f"{indent}  nested: {child_verdict} {child.path}")


def _summary(results: Sequence[ScanResult]) -> Dict[str, int]:
    summary = {"clean": 0, "suspicious": 0, "dangerous": 0, "unknown": 0}
    for result in results:
        summary[result.verdict] += 1
    return summary


def _exit_code(results: Sequence[ScanResult], fail_on: str, io_error: bool) -> int:
    if io_error:
        return 4
    if fail_on == "none":
        return 0
    summary = _summary(results)
    if summary["dangerous"]:
        return 2
    if fail_on == "suspicious" and summary["suspicious"]:
        return 1
    if summary["unknown"]:
        return 3
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        paths = _collect_paths(args.paths, args.recursive)
    except (IsADirectoryError, OSError) as exc:
        print(f"zipcheck: {exc}", file=sys.stderr)
        return 4
    if not paths:
        print("zipcheck: no archive files found", file=sys.stderr)
        return 4

    password, password_error = _resolve_password(args)
    if password_error is not None:
        return password_error

    limits = Limits(
        password=password,
        max_depth=max(0, args.depth),
        timeout=max(0.0, args.timeout),
        probe=args.probe,
        probe_limit=args.probe_limit,
        verify=args.verify or args.require_verified or args.production,
        verify_limit=args.verify_limit,
        require_verified=args.require_verified or args.production,
        min_expansion_bytes=args.min_size,
        suspicious_ratio=args.ratio,
        dangerous_ratio=max(args.dangerous_ratio, args.ratio),
        critical_ratio=max(args.dangerous_ratio * 100.0, args.ratio * 100.0),
    )

    color = (
        sys.stdout.isatty()
        and not args.no_color
        and os.environ.get("NO_COLOR") is None
    )
    started = time.monotonic()
    results: List[ScanResult] = []
    io_error = False
    for path in paths:
        try:
            result = scan_file(path, limits)
        except Exception as exc:  # defensive: a parser bug must not abort the run
            result = ScanResult(path=path, size=0, error=f"internal error: {exc}", unknown=True)
            io_error = True
        results.append(result)
        if not args.json and not args.quiet:
            _print_result(result, args, color)
            print()

    elapsed = time.monotonic() - started
    summary = _summary(results)

    if args.json:
        payload: Dict[str, Any] = {
            "tool": "zipcheck",
            "version": __version__,
            "elapsed_ms": round(elapsed * 1000, 3),
            "summary": summary,
            "results": [result.to_dict(sample_entries=max(args.entries, 25)) for result in results],
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.quiet:
        for result in results:
            print(f"{result.verdict.upper():10} {result.path}")
    else:
        print(
            f"{len(results)} file(s): {summary['dangerous']} dangerous, "
            f"{summary['suspicious']} suspicious, {summary['clean']} clean, "
            f"{summary['unknown']} unknown  ({elapsed:.2f}s)"
        )
        if not args.verbose:
            print("use -v for notes and member samples; --json for machine output")

    return _exit_code(results, args.fail_on, io_error)
