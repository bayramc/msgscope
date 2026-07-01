#!/usr/bin/env python3
"""Export known-good ``.msg`` files from a local Outlook install.

Windows only. Requires Outlook and pywin32 (``pip install pywin32``). Messages
are saved in the Unicode ``.msg`` format into ``corpus/good/`` (git-ignored),
giving you a real-world known-good corpus to validate ``msgscope`` against.

These exports may contain personal data. Keep them local and review before
sharing anything. See CONTRIBUTING.md.

Usage::

    python scripts/capture_corpus.py --folder Inbox --count 20 --out corpus/good
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Outlook constants (from the Outlook object model).
OL_MSG_UNICODE = 9  # OlSaveAsType.olMSGUnicode
OL_FOLDER_INBOX = 6  # OlDefaultFolders.olFolderInbox
OL_MAIL_ITEM_CLASS = 43  # OlObjectClass.olMail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", default="Inbox", help="Outlook folder to export from")
    parser.add_argument("--count", type=int, default=20, help="max messages to export")
    parser.add_argument("--out", default="corpus/good", help="output directory")
    parser.add_argument("--prefix", default="good", help="filename prefix for exported messages")
    args = parser.parse_args(argv)

    try:
        import win32com.client  # type: ignore[import-not-found]
    except ImportError:
        print(
            "This script needs Windows + Outlook + pywin32 (pip install pywin32).",
            file=sys.stderr,
        )
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    app = win32com.client.Dispatch("Outlook.Application")
    namespace = app.GetNamespace("MAPI")
    folder = _find_folder(namespace, args.folder)
    if folder is None:
        print(f"error: Outlook folder not found: {args.folder}", file=sys.stderr)
        return 3

    exported = 0
    for item in folder.Items:
        if exported >= args.count:
            break
        if getattr(item, "Class", None) != OL_MAIL_ITEM_CLASS:
            continue
        dest = out / f"{args.prefix}_{exported:04d}.msg"
        item.SaveAs(str(dest.resolve()), OL_MSG_UNICODE)
        exported += 1

    print(f"Exported {exported} message(s) to {out}/")
    print("These files are git-ignored. Review for PII before sharing.")
    print("Validate with:  pytest tests/test_corpus.py")
    return 0


def _find_folder(namespace: object, name: str):  # noqa: ANN202 (COM object)
    """Return the Outlook folder matching *name*, defaulting to the Inbox."""
    inbox = namespace.GetDefaultFolder(OL_FOLDER_INBOX)  # type: ignore[attr-defined]
    if name.lower() == "inbox":
        return inbox
    for folder in inbox.Parent.Folders:
        if folder.Name.lower() == name.lower():
            return folder
    return None


if __name__ == "__main__":
    raise SystemExit(main())
