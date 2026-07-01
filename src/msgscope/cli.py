"""Command-line interface.

``msgscope inspect FILE...`` reads each ``.msg`` file (never writing to it),
runs the registered checks, and prints a terminal or JSON report.

Exit codes (a verdict is never implied by the exit status by default):

* ``0``  - ran successfully.
* ``10`` - ``--fail-on`` set and at least one finding met the threshold.
* ``3``  - an input could not be read or was not a CFB container.
* ``2``  - command-line usage error (from argparse).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

from . import __version__, engine
from .container import MsgContainer
from .engine import Report
from .findings import SEVERITY_BY_NAME, Severity
from .report import render_text, report_to_json

EXIT_OK = 0
EXIT_INPUT_ERROR = 3
EXIT_FAIL_ON = 10

# Deterministic reference clock for --reproducible when none is supplied.
_REPRO_REFERENCE = _dt.datetime(2100, 1, 1, tzinfo=_dt.UTC)


def _load_checks() -> None:
    # Importing the package registers all built-ins.
    from . import checks  # noqa: F401

    engine.discover_plugins()


def _parse_csv(value: str | None) -> set[str] | None:
    if not value:
        return None
    return {item.strip() for item in value.split(",") if item.strip()}


def _parse_reference_time(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    dt = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.UTC)
    return dt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="msgscope",
        description=(
            "Inspect Outlook .msg files for structural anomalies. Reports indicators "
            "with evidence, never a verdict. Read-only."
        ),
    )
    parser.add_argument("--version", action="version", version=f"msgscope {__version__}")

    sub = parser.add_subparsers(dest="command")
    insp = sub.add_parser("inspect", help="inspect one or more .msg files")
    insp.add_argument("files", nargs="*", help="paths to .msg files")
    insp.add_argument("--format", choices=("text", "json"), default="text")
    insp.add_argument("--output", "-o", help="write report to a file instead of stdout")
    insp.add_argument("--checks", help="comma-separated check ids to run (default: all)")
    insp.add_argument("--exclude", help="comma-separated check ids to skip")
    insp.add_argument("--list-checks", action="store_true", help="list checks and exit")
    insp.add_argument("--reproducible", action="store_true", help="omit volatile run metadata")
    insp.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    insp.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_BY_NAME),
        help="exit 10 if any finding is at or above this severity",
    )
    insp.add_argument(
        "--reference-time",
        help="ISO-8601 reference clock for 'future timestamp' checks",
    )
    return parser


def _print_check_list() -> None:
    for check in engine.registered_checks():
        sys.stdout.write(f"{check.id:<18} {check.default_severity.value:<7} {check.title}\n")


def _run_inspect(args: argparse.Namespace, raw_argv: list[str]) -> int:
    _load_checks()

    if args.list_checks:
        _print_check_list()
        return EXIT_OK

    if not args.files:
        print("error: no input files (use 'msgscope inspect FILE ...')", file=sys.stderr)
        return EXIT_INPUT_ERROR

    select = _parse_csv(args.checks)
    exclude = _parse_csv(args.exclude)
    reference_time = _parse_reference_time(args.reference_time)
    if args.reproducible and reference_time is None:
        reference_time = _REPRO_REFERENCE
    fail_on = SEVERITY_BY_NAME[args.fail_on] if args.fail_on else None

    argv = [] if args.reproducible else list(raw_argv)

    reports: list[Report] = []
    any_input_error = False
    any_fail = False

    for file in args.files:
        path = Path(file)
        if not path.exists():
            print(f"error: no such file: {file}", file=sys.stderr)
            any_input_error = True
            continue
        try:
            with MsgContainer(path) as container:
                report = engine.analyze(
                    container,
                    select=select,
                    exclude=exclude,
                    reference_time=reference_time,
                    reproducible=args.reproducible,
                    argv=argv,
                )
        except OSError as exc:
            print(f"error: cannot read {file}: {exc}", file=sys.stderr)
            any_input_error = True
            continue

        reports.append(report)
        if not report.is_cfb:
            any_input_error = True
        elif fail_on is not None and _meets(report.max_severity(), fail_on):
            any_fail = True

    _emit(reports, args)

    if any_input_error:
        return EXIT_INPUT_ERROR
    if any_fail:
        return EXIT_FAIL_ON
    return EXIT_OK


def _meets(sev: Severity | None, threshold: Severity) -> bool:
    return sev is not None and sev.rank >= threshold.rank


def _emit(reports: list[Report], args: argparse.Namespace) -> None:
    if args.format == "json":
        if len(reports) == 1:
            text = report_to_json(reports[0])
        else:
            import json

            from .report.json_report import report_to_dict

            text = (
                json.dumps(
                    [report_to_dict(r) for r in reports],
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
    else:
        color = (not args.no_color) and sys.stdout.isatty()
        chunks = [render_text(r, color=color) for r in reports]
        text = "\n".join(chunks)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "inspect":
        return _run_inspect(args, raw_argv)
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
