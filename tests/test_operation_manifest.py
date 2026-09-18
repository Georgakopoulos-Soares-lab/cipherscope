"""The native operation manifest and the Python operation table must agree.

Both frontends normalize to the same canonical operation names; this test is
what keeps `native/openfhe/openfhe-1.5.operations.json` and
`cipherscope.compatibility.CORE_OPERATIONS` from drifting apart.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cipherscope.compatibility import CORE_OPERATIONS

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "native" / "openfhe" / "openfhe-1.5.operations.json"


class OperationManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.by_name = {op["canonical_name"]: op for op in self.manifest["operations"]}

    def test_every_python_operation_is_in_the_manifest_with_the_same_semantics(self) -> None:
        self.assertEqual(set(self.by_name), set(CORE_OPERATIONS))
        for name, spec in CORE_OPERATIONS.items():
            with self.subTest(operation=name):
                entry = self.by_name[name]
                self.assertEqual(entry["kind"], spec.event_kind)
                self.assertEqual(entry["default_overload"], spec.default_overload)
                self.assertEqual(entry["has_ciphertext_output"], spec.has_ciphertext_output)
                self.assertEqual(entry["mutated_argument"] is not None, spec.mutated_ciphertext_count > 0)
                expected_inputs = None if spec.ciphertext_input_indices is None else list(spec.ciphertext_input_indices)
                self.assertEqual(entry["ciphertext_input_indices"], expected_inputs)

    def test_operator_aliases_target_manifest_operations(self) -> None:
        for alias, target in self.manifest["operator_aliases"].items():
            if alias == "comment":
                continue
            with self.subTest(alias=alias):
                self.assertIn(target, self.by_name)

    def test_manifest_is_versioned(self) -> None:
        self.assertEqual(self.manifest["name"], "openfhe-1.5-v1")
        self.assertTrue(self.manifest["supported_toolchain"]["versions_tested"])


if __name__ == "__main__":
    unittest.main()
