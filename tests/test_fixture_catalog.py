"""Integrity tests for the repository's wholly synthetic fixture corpus."""

from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path, PurePosixPath


FIXTURE_ROOT = Path(__file__).with_name("fixtures")
CATALOG_PATH = FIXTURE_ROOT / "corpus.json"

EXPECTED_TOTAL = 44
EXPECTED_KIND_COUNTS = {
    "opaque_stack_text": 18,
    "ciphertext_graph_json": 12,
    "semantic_trace_json": 14,
}
EXPECTED_STACK_LANGUAGE_COUNTS = {
    "python": 2,
    "javascript": 2,
    "typescript": 2,
    "java": 2,
    "go": 2,
    "rust": 2,
    "csharp": 2,
    "ruby": 2,
    "native": 2,
}
EXPECTED_PROVENANCE = {
    "kind": "synthetic",
    "source_url": None,
    "license": "NOASSERTION",
    "sensitive": False,
}


class FixtureCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        cls.entries = cls.catalog["fixtures"]

    def test_catalog_has_expected_version_and_counts(self) -> None:
        self.assertEqual(self.catalog["catalog_version"], "1.0.0")
        self.assertEqual(len(self.entries), EXPECTED_TOTAL)
        self.assertEqual(
            Counter(entry["artifact_kind"] for entry in self.entries),
            EXPECTED_KIND_COUNTS,
        )

    def test_ids_and_paths_are_unique_and_stable(self) -> None:
        ids = [entry["id"] for entry in self.entries]
        paths = [entry["path"] for entry in self.entries]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(paths), len(set(paths)))
        for fixture_id in ids:
            self.assertRegex(fixture_id, r"^[a-z0-9]+(?:[._][a-z0-9]+)*$")

    def test_catalog_paths_are_relative_safe_and_complete(self) -> None:
        catalog_paths = set()
        for entry in self.entries:
            relative = PurePosixPath(entry["path"])
            self.assertFalse(relative.is_absolute(), entry["id"])
            self.assertNotIn("..", relative.parts, entry["id"])
            fixture_path = FIXTURE_ROOT.joinpath(*relative.parts)
            self.assertTrue(fixture_path.is_file(), entry["id"])
            catalog_paths.add(relative.as_posix())

        artifact_paths = {
            path.relative_to(FIXTURE_ROOT).as_posix()
            for directory in ("ancillary", "graphs", "traces")
            for path in (FIXTURE_ROOT / directory).rglob("*")
            if path.is_file()
        }
        self.assertEqual(catalog_paths, artifact_paths)

    def test_provenance_is_explicit_synthetic_and_non_sensitive(self) -> None:
        for entry in self.entries:
            with self.subTest(fixture=entry["id"]):
                self.assertEqual(entry["provenance"], EXPECTED_PROVENANCE)
                self.assertIs(entry["provenance"]["sensitive"], False)

    def test_expected_stage_and_code_are_present(self) -> None:
        allowed_outcomes = {"accept", "reject", "not_applicable"}
        allowed_stages = {
            "json_decode",
            "graph_validation",
            "trace_validation",
            "opaque_text",
        }
        for entry in self.entries:
            expected = entry["expected"]
            with self.subTest(fixture=entry["id"]):
                self.assertEqual(set(expected), {"outcome", "stage", "code"})
                self.assertIn(expected["outcome"], allowed_outcomes)
                self.assertIn(expected["stage"], allowed_stages)
                self.assertIsInstance(expected["code"], str)
                self.assertTrue(expected["code"])

    def test_every_fixture_is_utf8(self) -> None:
        for entry in self.entries:
            fixture_path = FIXTURE_ROOT / entry["path"]
            with self.subTest(fixture=entry["id"]):
                decoded = fixture_path.read_bytes().decode("utf-8", errors="strict")
                self.assertTrue(decoded.strip())

    def test_expected_accept_json_is_parseable_object(self) -> None:
        accepted = [
            entry
            for entry in self.entries
            if entry["language"] == "json" and entry["expected"]["outcome"] == "accept"
        ]
        self.assertEqual(len(accepted), 14)
        for entry in accepted:
            with self.subTest(fixture=entry["id"]):
                value = json.loads(
                    (FIXTURE_ROOT / entry["path"]).read_text(encoding="utf-8")
                )
                self.assertIsInstance(value, dict)
                self.assertEqual(value["schema_version"], "1.0.0")

    def test_only_malformed_cases_fail_json_decode(self) -> None:
        json_entries = [entry for entry in self.entries if entry["language"] == "json"]
        malformed_count = 0
        for entry in json_entries:
            raw = (FIXTURE_ROOT / entry["path"]).read_text(encoding="utf-8")
            if entry["expected"]["stage"] == "json_decode":
                malformed_count += 1
                with self.subTest(fixture=entry["id"]):
                    with self.assertRaises(json.JSONDecodeError):
                        json.loads(raw)
            else:
                with self.subTest(fixture=entry["id"]):
                    self.assertIsInstance(json.loads(raw), dict)
        self.assertEqual(malformed_count, 2)

    def test_parseable_json_cases_declare_synthetic_contract(self) -> None:
        for entry in self.entries:
            if (
                entry["language"] != "json"
                or entry["expected"]["stage"] == "json_decode"
            ):
                continue
            value = json.loads(
                (FIXTURE_ROOT / entry["path"]).read_text(encoding="utf-8")
            )
            marker = (
                value["synthetic_contract"]
                if entry["artifact_kind"] == "ciphertext_graph_json"
                else value["run"]["synthetic_contract"]
            )
            with self.subTest(fixture=entry["id"]):
                self.assertIs(marker, True)

    def test_exactly_two_opaque_samples_per_language(self) -> None:
        stacks = [
            entry
            for entry in self.entries
            if entry["artifact_kind"] == "opaque_stack_text"
        ]
        self.assertEqual(len(stacks), 18)
        self.assertEqual(
            Counter(entry["language"] for entry in stacks),
            EXPECTED_STACK_LANGUAGE_COUNTS,
        )
        for entry in stacks:
            with self.subTest(fixture=entry["id"]):
                self.assertEqual(entry["expected"]["outcome"], "not_applicable")
                self.assertTrue(
                    {"ancillary", "opaque", "not_supported_runtime_input"}
                    <= set(entry["tags"])
                )

    def test_requested_stack_and_semantic_case_tags_are_covered(self) -> None:
        stack_tags = {
            tag
            for entry in self.entries
            if entry["artifact_kind"] == "opaque_stack_text"
            for tag in entry["tags"]
        }
        self.assertTrue(
            {
                "chained",
                "recursive",
                "async",
                "concurrent",
                "repeated_frames",
                "truncated",
                "unicode",
                "redacted_path",
                "escaping",
                "stack_limit",
            }
            <= stack_tags
        )

        semantic_tags = {
            tag
            for entry in self.entries
            if entry["language"] == "json"
            for tag in entry["tags"]
        }
        self.assertTrue(
            {
                "minimal",
                "deep",
                "repeated",
                "bootstrap",
                "disconnected",
                "cyclic",
                "dangling",
                "duplicate",
                "malformed",
                "unicode",
                "empty",
                "large_metadata",
                "adversarial_metadata",
            }
            <= semantic_tags
        )

    def test_readme_marks_stack_text_as_ancillary_only(self) -> None:
        readme = (FIXTURE_ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("test escaping", readme)
        self.assertIn("path redaction", readme)
        self.assertIn("stack-size limits", readme)
        self.assertIn("not supported cipherscope runtime inputs", readme)


if __name__ == "__main__":
    unittest.main()
