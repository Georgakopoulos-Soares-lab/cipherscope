"""Environment and immutable build-input checks for the real binding gate."""

from __future__ import annotations

import json
import os
import platform
import unittest
from pathlib import Path

from . import support


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class EnvironmentTests(unittest.TestCase):
    def test_env_01_primary_os_and_architecture(self) -> None:
        """ENV-01: the declared Linux lane has its exact OS and architecture."""

        snapshot = support.environment_snapshot()
        if support.LANE in {"primary-source-py311", "provisional-wheel-py312"}:
            self.assertEqual(snapshot["platform"], "Linux")
            self.assertEqual(snapshot["machine"], "x86_64")
            self.assertEqual(snapshot["os_release"].get("ID"), "ubuntu")
            self.assertEqual(snapshot["os_release"].get("VERSION_ID"), "24.04")
        elif support.LANE == "ls6-native-py311":
            # A bare-host lane: Linux x86_64 is required, the distribution is
            # recorded (Rocky Linux on Lonestar6) but deliberately not asserted.
            self.assertEqual(snapshot["platform"], "Linux")
            self.assertEqual(snapshot["machine"], "x86_64")
            self.assertTrue(snapshot["os_release"].get("ID"))
            self.assertTrue(snapshot["os_release"].get("VERSION_ID"))
        support.record("ENV-01", **snapshot)

    def test_env_02_cpython_version(self) -> None:
        """ENV-02: CPython matches the selected evidence lane."""

        expected_minor = {
            "primary-source-py311": (3, 11),
            "ls6-native-py311": (3, 11),
            "provisional-wheel-py312": (3, 12),
        }.get(support.LANE)
        self.assertEqual(platform.python_implementation(), "CPython")
        if expected_minor is not None:
            self.assertEqual(platform.python_version_tuple()[:2], tuple(map(str, expected_minor)))
        support.record(
            "ENV-02",
            implementation=platform.python_implementation(),
            version=platform.python_version(),
            expected_minor=expected_minor,
        )

    def test_env_03_distribution_or_source_pin(self) -> None:
        """ENV-03: installed wrapper provenance matches the selected lane."""

        installed = support.distribution_version()
        wrapper_commit = os.environ.get("CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT")
        if support.LANE == "provisional-wheel-py312":
            self.assertEqual(installed, support.GOLDEN["provisional_distribution"])
        elif support.LANE in {"primary-source-py311", "ls6-native-py311"}:
            self.assertEqual(wrapper_commit, support.GOLDEN["wrapper_commit"])
        elif installed is None:
            # A source-built developer wrapper has no pip metadata; the pinned
            # commit is its provenance, exactly as in the primary lane.
            self.assertEqual(wrapper_commit, support.GOLDEN["wrapper_commit"])
        support.record(
            "ENV-03",
            lane=support.LANE,
            distribution_version=installed,
            wrapper_commit=wrapper_commit,
        )

    def test_env_04_build_inputs_are_pinned(self) -> None:
        """ENV-04: exact wheel hash or source commits are fixed and recorded."""

        if support.LANE == "provisional-wheel-py312":
            requirements = (
                support.PROJECT_ROOT / "requirements" / "openfhe-ubuntu24-py312.txt"
            ).read_text(encoding="utf-8")
            self.assertIn(support.GOLDEN["provisional_wheel_sha256"], requirements)
            provenance = {
                "distribution": support.GOLDEN["provisional_distribution"],
                "wheel_sha256": support.GOLDEN["provisional_wheel_sha256"],
                "native_module_hashes": support.native_module_hashes(),
            }
        elif support.LANE in {"primary-source-py311", "ls6-native-py311"}:
            expected = {
                "wrapper_commit": support.GOLDEN["wrapper_commit"],
                "native_commit": support.GOLDEN["native_commit"],
            }
            observed = {
                "wrapper_commit": os.environ.get(
                    "CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT"
                ),
                "native_commit": os.environ.get("CIPHERSCOPE_OPENFHE_NATIVE_COMMIT"),
            }
            self.assertEqual(observed, expected)
            build_manifest = os.environ.get("CIPHERSCOPE_OPENFHE_BUILD_MANIFEST")
            self.assertIsNotNone(build_manifest)
            self.assertTrue(Path(str(build_manifest)).is_file())
            manifest = json.loads(
                Path(str(build_manifest)).read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["openfhe_python"]["commit"], expected["wrapper_commit"]
            )
            self.assertEqual(
                manifest["openfhe_native"]["commit"], expected["native_commit"]
            )
            self.assertTrue(manifest["openfhe_python"]["native_module_hashes"])
            self.assertTrue(manifest["toolchain"]["cxx"])
            provenance = {
                **observed,
                "build_manifest": manifest,
                "native_module_hashes": support.native_module_hashes(),
            }
        else:
            provenance = {"native_module_hashes": support.native_module_hashes()}
        self.assertTrue(provenance.get("native_module_hashes", True))
        support.record("ENV-04", **provenance)

    def test_env_05_import_and_native_word_size(self) -> None:
        """ENV-05: the native module imports and reports a supported word size."""

        native_int = support.require_openfhe().get_native_int()
        self.assertIn(native_int, {64, 128})
        support.record(
            "ENV-05",
            native_int=native_int,
            module_file=Path(support.require_openfhe().__file__).name,
        )


if __name__ == "__main__":
    unittest.main()
