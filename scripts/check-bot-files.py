#!/usr/bin/env python3
"""Fail closed unless bot configuration and key files have safe Unix metadata."""

from __future__ import annotations

import os
import stat
import sys


def refuse(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def inspect(path: str, *, private: bool) -> None:
    try:
        metadata = os.lstat(path)
    except OSError:
        refuse("b10x-bot credential input is unavailable")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
        refuse("b10x-bot credential input must be a current-user-owned regular file")
    unsafe_mask = 0o077 if private else 0o022
    if stat.S_IMODE(metadata.st_mode) & unsafe_mask:
        qualifier = "owner-only" if private else "not group/world-writable"
        refuse(f"b10x-bot credential input must be {qualifier}")
    if not os.access(path, os.R_OK):
        refuse("b10x-bot credential input is not readable")


def main() -> None:
    if len(sys.argv) != 3:
        refuse("usage: check-bot-files.py CONFIG PRIVATE_KEY")
    inspect(sys.argv[1], private=False)
    inspect(sys.argv[2], private=True)


if __name__ == "__main__":
    main()
