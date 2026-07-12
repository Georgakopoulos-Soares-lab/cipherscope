"""Privacy and untrusted-text regressions for default-mode artifacts."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import cipherscope
from cipherscope.security import sanitize_untrusted_text
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures"


class PrivacyTests(unittest.TestCase):
    def test_default_trace_never_calls_repr_or_serializes_arbitrary_attributes(
        self,
    ) -> None:
        class SensitiveCiphertext(FakeCiphertext):
            plaintext_sentinel = "PLAINTEXT-MUST-NOT-LEAK"

            def __repr__(self) -> str:  # pragma: no cover - failure proves a leak
                raise AssertionError("CipherScope called repr on a ciphertext")

        with cipherscope.trace(FakeCryptoContext()) as session:
            session.context.EvalBootstrap(SensitiveCiphertext())
        serialized = json.dumps(session.to_trace())
        self.assertNotIn("PLAINTEXT-MUST-NOT-LEAK", serialized)
        self.assertNotRegex(serialized, r"0x[0-9a-fA-F]{6,}")

    def test_plaintext_or_key_shaped_operand_values_are_not_serialized(self) -> None:
        class SensitiveOperand:
            secret = "OPERAND-VALUE-MUST-NOT-LEAK"

            def __repr__(self) -> str:  # pragma: no cover - failure proves a leak
                raise AssertionError("CipherScope represented a sensitive operand")

        class OperandBackend(FakeCryptoContext):
            def EvalMult(
                self,
                left: FakeCiphertext,
                right: SensitiveOperand,
            ) -> FakeCiphertext:
                del right
                self._called("EvalMult")
                return self._fresh(left, level=left.level + 1, noise=2)

        with cipherscope.trace(OperandBackend()) as session:
            session.context.EvalMult(FakeCiphertext(), SensitiveOperand())
        trace = session.to_trace()
        serialized = json.dumps(trace)
        self.assertNotIn("OPERAND-VALUE-MUST-NOT-LEAK", serialized)
        self.assertEqual(trace["events"][0]["operand_kinds"][1], "unknown")

    def test_encrypt_decrypt_never_serialize_or_represent_keys_and_plaintexts(
        self,
    ) -> None:
        probed_getters: list[str] = []

        class SensitiveValue:
            sentinel = "ENCRYPTION-INPUT-MUST-NOT-LEAK"

            def __repr__(self) -> str:  # pragma: no cover - failure proves a leak
                raise AssertionError("CipherScope represented key/plaintext material")

            def __getattribute__(self, name: str) -> object:
                if name in {"GetLevel", "GetNoiseScaleDeg"}:
                    probed_getters.append(name)
                    raise AssertionError("CipherScope probed key/plaintext metadata")
                return object.__getattribute__(self, name)

        backend = FakeCryptoContext()
        public_key = SensitiveValue()
        private_key = SensitiveValue()
        plaintext = SensitiveValue()
        with cipherscope.trace(backend) as session:
            ciphertext = session.context.Encrypt(public_key, plaintext)
            session.context.Decrypt(ciphertext, private_key)
            session.context.EvalRotateKeyGen(private_key, [1, 2])

        serialized = json.dumps(session.to_trace())
        self.assertNotIn("ENCRYPTION-INPUT-MUST-NOT-LEAK", serialized)
        self.assertNotRegex(serialized, r"0x[0-9a-fA-F]{6,}")
        self.assertEqual(probed_getters, [])

    def test_opaque_stack_corpus_is_only_redacted_bounded_and_escaped(self) -> None:
        paths = sorted((FIXTURE_ROOT / "ancillary" / "stacks").glob("*.txt"))
        self.assertEqual(len(paths), 18)
        for path in paths:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                result = sanitize_untrusted_text(
                    source + "\n<script>alert('x')</script>",
                    max_bytes=256,
                    for_html=True,
                )
                self.assertLessEqual(
                    len(result.text.replace("&lt;", "<").encode("utf-8")),
                    512,
                )
                self.assertNotIn("<script>", result.text)
                self.assertNotIn("/Users/", result.text)
                self.assertNotRegex(result.text, r"[A-Za-z]:\\")

    def test_utf8_limits_cover_below_at_and_above_boundary(self) -> None:
        for size, truncated in ((31, False), (32, False), (33, True)):
            with self.subTest(size=size):
                result = sanitize_untrusted_text("x" * size, max_bytes=32)
                self.assertEqual(result.truncated, truncated)
                self.assertLessEqual(len(result.text.encode("utf-8")), 32)
        unicode_result = sanitize_untrusted_text("λ" * 40, max_bytes=31)
        unicode_result.text.encode("utf-8")
        self.assertLessEqual(len(unicode_result.text.encode("utf-8")), 31)

    def test_absolute_paths_are_redacted_without_parsing_stack_semantics(self) -> None:
        value = "at /Users/alice/private/model.py:7 and C:\\secret\\worker.cs:9"
        result = sanitize_untrusted_text(value, max_bytes=200)
        self.assertEqual(result.text.count("<redacted-path>"), 2)
        self.assertFalse(result.truncated)


if __name__ == "__main__":
    unittest.main()
