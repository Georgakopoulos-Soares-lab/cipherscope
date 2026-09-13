#!/usr/bin/env python3
"""Regenerate every paper table under evaluation/tables from the raw records.

No table is edited by hand. Delete evaluation/tables and run this again; the
output is byte-for-byte identical for the same inputs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from cipherscope.tables import ContractError, generate_tables


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation-dir", type=Path, default=HERE)
    parser.add_argument("--schema", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    try:
        manifest = generate_tables(
            args.evaluation_dir, schema_path=args.schema, output_dir=args.output
        )
    except (ContractError, OSError, ValueError) as error:
        print(f"generate_paper_tables: refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
