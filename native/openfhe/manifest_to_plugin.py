#!/usr/bin/env python3
"""Render the JSON operation manifest as the line format the GCC plugin reads.

    python3 native/openfhe/manifest_to_plugin.py native/openfhe/openfhe-1.5.operations.json > out.txt
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ALIAS = re.compile(r"lbcrypto::(operator\S+?)<\*>\((.*)\)")


def render(manifest: dict) -> str:
    lines = [f"name {manifest['name']}"]
    for op in manifest["operations"]:
        lines.append(f"op {op['canonical_name']}")
    for alias, target in manifest.get("operator_aliases", {}).items():
        match = ALIAS.match(alias)
        if not match:
            continue
        arity = len([part for part in match.group(2).split(",") if part.strip()])
        lines.append(f"alias {match.group(1)}/{arity} {target}")
    for method, target in manifest.get("method_aliases", {}).items():
        if method != "comment":
            lines.append(f"method {method} {target}")
    allowed = manifest.get("allowed_nonsemantic", {})
    for name in allowed.get("names", []):
        lines.append(f"allow {name}")
    for prefix in allowed.get("prefixes", []):
        lines.append(f"allow-prefix {prefix}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    sys.stdout.write(render(document))
