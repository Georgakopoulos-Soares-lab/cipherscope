#!/usr/bin/env python3
"""Run an unmodified OpenFHE script with factory-level CipherScope attachment."""

from __future__ import annotations

import argparse
import runpy
import sys
from pathlib import Path
from typing import Any

import cipherscope
import openfhe


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", type=Path)
    parser.add_argument("script_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    script = args.script.resolve()
    if not script.is_file():
        parser.error(f"target script does not exist: {script}")

    original_factory = openfhe.GenCryptoContext

    def traced_factory(*factory_args: Any, **factory_kwargs: Any) -> Any:
        native_context = original_factory(*factory_args, **factory_kwargs)
        # The context cannot report its security level; the params object can.
        parameters = factory_args[0] if factory_args else factory_kwargs.get("params")
        return cipherscope.attach(native_context, parameters=parameters)

    old_argv = sys.argv
    openfhe.GenCryptoContext = traced_factory
    try:
        forwarded = list(args.script_args)
        if forwarded and forwarded[0] == "--":
            forwarded.pop(0)
        sys.argv = [str(script), *forwarded]
        runpy.run_path(str(script), run_name="__main__")
    finally:
        sys.argv = old_argv
        openfhe.GenCryptoContext = original_factory
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
