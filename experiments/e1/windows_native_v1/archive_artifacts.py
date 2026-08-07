#!/usr/bin/env python3
"""Deterministic ZIP archiver for the Windows-native E1 release.

Thin wrapper over the shared E0-H ``deterministic_zip`` helper so the E1
release produces byte-reproducible deflated ZIP archives (fixed timestamp,
fixed ordering, fixed permissions).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from csd_foundry.empirical.e0h.windows_native import deterministic_zip


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()

    root = args.root.resolve()
    members: dict[str, Path] = {}
    for raw in args.paths:
        path = (root / raw).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"archive path escapes root: {raw}") from exc
        if path.is_dir():
            for child in sorted(item for item in path.rglob("*") if item.is_file()):
                members[child.relative_to(root).as_posix()] = child
        elif path.is_file():
            members[relative.as_posix()] = path
        else:
            raise FileNotFoundError(path)
    print(deterministic_zip(args.output, members))


if __name__ == "__main__":
    main()
