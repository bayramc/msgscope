# Contributing to msgscope

Thanks for helping build a tool forensic examiners can trust. The guiding
principle: **msgscope reports indicators with evidence, never verdicts.** Keep
that in mind for every change.

## Development setup

```console
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Run the checks the way CI does:

```console
ruff check .
ruff format --check .
mypy
pytest
```

## Repository layout

```
src/msgscope/          # package
  container.py         # the ONLY olefile access layer; checks use this, not olefile
  checks/              # one detector per file
  report/              # json + text renderers
tests/
  fixtures/            # cfb_writer.py (CFB writer) + builders.py (msg assembler)
  test_<check>.py      # one test module per detector
docs/checks/           # one plain-language doc per detector
```

## Adding a new detector

1. **Implement** a `Check` subclass in `src/msgscope/checks/your_check.py`. Give
   it a stable `id`, a `title`, a `default_severity`, and a `run(ctx)` that
   yields `Finding`s. Read only through `ctx.container` — never import `olefile`
   in a check.
2. **Register** it: add the class to `BUILTIN_CHECKS` in
   `src/msgscope/checks/__init__.py`. (External packages instead advertise an
   entry point in the `msgscope.checks` group.)
3. **Write evidence that a layperson can follow.** Every finding needs
   `summary_plain`, `why_it_matters`, and concrete `evidence` (object, stream,
   byte offset, observed vs expected). Set `confidence` honestly.
4. **Add a fixture-driven test** in `tests/test_your_check.py`: build a message
   with the anomalycheck using `fixtures/builders.py`, assert your detector fires
   **and that no other detector fires** on it, plus a negative case that stays
   silent. The baseline (`good_message`) must remain finding-free.
5. **Document it** in `docs/checks/<ID>.md`: plain-language description, how it
   works, the spec reference, and its known benign causes.

### Publishing a detector as a plugin

```toml
# in your own package's pyproject.toml
[project.entry-points."msgscope.checks"]
my_detector = "my_pkg.checks:MyCheck"
```

`msgscope` discovers it automatically at runtime.

## Test corpus

- **Never commit real evidence or PII.** Only the tiny, synthetic, content-free
  files under `sample/` are tracked.
- Keep real known-good exports and third-party-generated known-synthetic files
  locally under `corpus/` (git-ignored). To source known-good files, save
  messages from a real Outlook install (a `pywin32` script can automate this on
  Windows — run it locally, not in CI). Scrub subjects, bodies, addresses, and
  names before sharing anything.
- CI depends only on the in-repo CFB writer, so tests are reproducible and
  license-clean.

## Commits and pull requests

- Keep changes focused; one detector or fix per PR where possible.
- Ensure `ruff`, `mypy`, and `pytest` all pass locally.
- Describe the forensic rationale for new detectors and cite the spec.

## Security disclosure

Please report security issues privately to the maintainers rather than opening a
public issue.
