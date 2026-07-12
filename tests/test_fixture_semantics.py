"""Execute every structured fixture against the runtime validator."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cipherscope.validation import (
    StrictJSONError,
    load_json_file,
    validate_graph,
    validate_trace,
)


FIXTURE_ROOT = Path(__file__).with_name("fixtures")


class FixtureSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(
            (FIXTURE_ROOT / "corpus.json").read_text(encoding="utf-8")
        )

    def test_all_structured_fixtures_match_declared_outcome_and_code(self) -> None:
        entries = [
            entry
            for entry in self.catalog["fixtures"]
            if entry["artifact_kind"]
            in {"semantic_trace_json", "ciphertext_graph_json"}
        ]
        self.assertEqual(len(entries), 26)
        for entry in entries:
            expected = entry["expected"]
            path = FIXTURE_ROOT / entry["path"]
            with self.subTest(fixture=entry["id"]):
                if expected["stage"] == "json_decode":
                    with self.assertRaises(StrictJSONError) as caught:
                        load_json_file(path)
                    self.assertEqual(caught.exception.code, expected["code"])
                    continue

                document = load_json_file(path)
                result = (
                    validate_trace(document)
                    if entry["artifact_kind"] == "semantic_trace_json"
                    else validate_graph(document)
                )
                if expected["outcome"] == "accept":
                    self.assertTrue(
                        result.valid,
                        [issue.to_dict() for issue in result.errors],
                    )
                else:
                    self.assertFalse(result.valid)
                    self.assertIn(
                        expected["code"],
                        {issue.code for issue in result.errors},
                    )


if __name__ == "__main__":
    unittest.main()
