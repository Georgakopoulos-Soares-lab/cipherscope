"""Every run records the lane, wrapper provenance, and CipherScope commit."""

from __future__ import annotations

import hashlib
import re
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

import cipherscope
from cipherscope import fingerprint
from cipherscope.state import TOOL_VERSION
from cipherscope.testing import FakeCryptoContext

COMMIT = re.compile(r"^[0-9a-f]{40}$")


class FingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        fingerprint.build_fingerprint.cache_clear()
        self.addCleanup(fingerprint.build_fingerprint.cache_clear)

    def test_fingerprint_is_in_every_trace_runtime(self) -> None:
        with cipherscope.trace(FakeCryptoContext()) as session:
            pass
        runtime = session.to_trace()["run"]["runtime"]
        self.assertEqual(runtime["cipherscope_version"], TOOL_VERSION)
        self.assertIsInstance(runtime["lane"], str)
        self.assertTrue(runtime["lane"])
        commit = runtime["cipherscope_commit"]
        self.assertTrue(commit is None or COMMIT.match(commit), commit)
        self.assertIn(runtime["cipherscope_dirty"], {True, False, None})
        self.assertIsInstance(runtime["openfhe_native_module_hashes"], dict)

    def test_lane_comes_from_the_environment(self) -> None:
        with mock.patch.dict("os.environ", {"CIPHERSCOPE_OPENFHE_LANE": "primary-source-py311"}):
            self.assertEqual(fingerprint.build_fingerprint()["lane"], "primary-source-py311")

    def test_native_hashes_only_for_a_loaded_wrapper(self) -> None:
        with mock.patch.dict(sys.modules, {"openfhe": None}):
            self.assertEqual(fingerprint._native_module_hashes(), {})

        with mock.patch.dict(sys.modules, {}, clear=False):
            sys.modules.pop("openfhe", None)
            import tempfile

            with tempfile.TemporaryDirectory() as temporary:
                package = Path(temporary) / "openfhe"
                package.mkdir()
                (package / "__init__.py").write_text("", encoding="utf-8")
                native = package / "openfhe.cpython-311-darwin.so"
                native.write_bytes(b"not really native")
                module = types.ModuleType("openfhe")
                module.__file__ = str(package / "__init__.py")
                with mock.patch.dict(sys.modules, {"openfhe": module}):
                    hashes = fingerprint._native_module_hashes()
                self.assertEqual(
                    hashes, {native.name: hashlib.sha256(b"not really native").hexdigest()}
                )

    def test_git_failure_yields_none_not_an_error(self) -> None:
        with mock.patch.object(fingerprint, "_git", return_value=None):
            result = fingerprint.build_fingerprint()
        self.assertIsNone(result["cipherscope_commit"])
        self.assertIsNone(result["cipherscope_dirty"])


if __name__ == "__main__":
    unittest.main()
