"""ARTIFACT.md, the Makefile, and the raw-result checksums must agree with the tree."""

from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / "docs" / "ARTIFACT.md"
MAKEFILE = ROOT / "Makefile"
RAW = ROOT / "evaluation" / "raw"
BACKTICK_PATH = re.compile(r"`([A-Za-z0-9_./-]+\.(?:md|json|csv|py|yaml))`")
# Files the mapping table may name before they exist (future tables / LS6 inputs).
ALLOWED_MISSING = {
    "evaluation/tables/coverage.csv",
    "evaluation/tables/precision.csv",
    "evaluation/adjudication/findings.csv",
    "workload_runs.csv",
    "findings.csv",
}


class ArtifactGuideTests(unittest.TestCase):
    def test_every_referenced_path_exists_or_is_declared_pending(self) -> None:
        text = ARTIFACT.read_text(encoding="utf-8")
        # Only repository-relative paths; bare names and the parent repo's files are prose.
        referenced = sorted({match for match in BACKTICK_PATH.findall(text) if "/" in match and "*" not in match})
        self.assertTrue(referenced)
        for path in referenced:
            if path in ALLOWED_MISSING:
                continue
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists(), f"ARTIFACT.md references missing {path}")

    def test_makefile_has_the_artifact_targets(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        for target in ("artifact-smoke:", "reproduce-small:", "verify-checksums:", "checksums:", "test:"):
            self.assertIn(target, text)

    def test_raw_checksums_match(self) -> None:
        manifest = RAW / "CHECKSUMS.sha256"
        self.assertTrue(manifest.is_file())
        listed: set[str] = set()
        for line in manifest.read_text(encoding="utf-8").splitlines():
            digest, _, name = line.partition("  ")
            relative = name.strip().removeprefix("./")
            listed.add(relative)
            with self.subTest(file=relative):
                actual = hashlib.sha256((RAW / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, digest, f"{relative} changed; run `make checksums`")
        present = {
            str(path.relative_to(RAW)) for path in RAW.rglob("*") if path.is_file() and path.name != "CHECKSUMS.sha256"
        }
        self.assertEqual(present, listed, "raw files without a checksum; run `make checksums`")


if __name__ == "__main__":
    unittest.main()
