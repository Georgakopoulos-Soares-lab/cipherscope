#!/usr/bin/env python3
"""Write a CipherScope demonstration bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from cipherscope.demo import write_demo


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    destination = write_demo(args.output)
    print(f"Wrote synthetic CipherScope bundle to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
