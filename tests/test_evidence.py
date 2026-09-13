"""docs/evidence.md must agree with the archived feasibility artifacts."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence.md"
ARTIFACTS = ROOT / "artifact" / "feasibility"
ROW = re.compile(r"^\|\s*`(?P<lane>[^`]+)`\s*\|(?P<rest>.*)\|\s*$")
COUNTS = re.compile(r"^(\d+)\s*/\s*(\d+)\s*/\s*(\d+)$")


def _rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in EVIDENCE.read_text(encoding="utf-8").splitlines():
        match = ROW.match(line)
        if match:
            cells = [cell.strip() for cell in match.group("rest").split("|")]
            rows[match.group("lane")] = cells
    return rows


class EvidenceTableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = _rows()
        self.assertTrue(self.rows, "no lane rows found in docs/evidence.md")

    def test_every_archived_lane_has_a_matching_row(self) -> None:
        archived = sorted(path.name for path in ARTIFACTS.iterdir() if path.is_dir())
        self.assertTrue(archived)
        for lane in archived:
            with self.subTest(lane=lane):
                self.assertIn(lane, self.rows, f"{lane} has no row in docs/evidence.md")
                document = json.loads(
                    (ARTIFACTS / lane / "feasibility.json").read_text(encoding="utf-8")
                )
                platform_, python, _wrapper, status, counts, authoritative, artifact = self.rows[lane]
                self.assertEqual(status.strip("`"), document["status"])
                match = COUNTS.match(counts)
                self.assertIsNotNone(match, counts)
                summary = document["summary"]
                self.assertEqual(
                    tuple(int(value) for value in match.groups()),
                    (summary["pass"], summary["skip"], summary["total"]),
                )
                self.assertEqual(
                    authoritative.startswith("yes"),
                    bool(document["authoritative_for_primary_target"]),
                )
                self.assertIn(f"artifact/feasibility/{lane}/feasibility.json", artifact)
                environment = document["environment"]
                self.assertIn(environment["python"], python)
                self.assertIn(environment["machine"], platform_)

    def test_unarchived_primary_lane_is_declared_missing(self) -> None:
        primary = ARTIFACTS / "primary-source-py311" / "feasibility.json"
        row = self.rows["primary-source-py311"]
        status, counts, artifact = row[3], row[4], row[6]
        if primary.is_file():
            self.assertNotEqual(status, "not archived")
            self.assertNotIn("missing", artifact)
        else:
            self.assertEqual(status, "not archived")
            self.assertEqual(counts, "—")
            self.assertIn("missing", artifact)


if __name__ == "__main__":
    unittest.main()
