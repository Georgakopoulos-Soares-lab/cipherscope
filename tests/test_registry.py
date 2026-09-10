"""Tests for ciphertext identity and weak-reference cleanup."""

from __future__ import annotations

import gc
import unittest
import weakref

from cipherscope.registry import CiphertextRegistry
from cipherscope.state import CiphertextMetadata


class _Ciphertext:
    pass


class CiphertextRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = CiphertextRegistry(
            lambda _value: CiphertextMetadata(level=0, noise_scale_degree=1)
        )

    def test_live_aliases_share_one_ciphertext_id(self) -> None:
        ciphertext = _Ciphertext()

        first = self.registry.observe_input(ciphertext)
        second = self.registry.observe_input(ciphertext)

        self.assertEqual(first.ciphertext_id, "ct_0001:v0")
        self.assertEqual(second.ciphertext_id, first.ciphertext_id)

    def test_output_alias_creates_the_next_version(self) -> None:
        ciphertext = _Ciphertext()
        first = self.registry.observe_input(ciphertext)

        output = self.registry.observe_output(
            ciphertext,
            event_id="event_0001",
            parent_ids=[first.ciphertext_id],
        )

        self.assertEqual(output.ciphertext_id, "ct_0001:v1")
        state = self.registry.state(output.ciphertext_id)
        self.assertEqual(state.parent_ids, ("ct_0001:v0",))
        self.assertEqual(state.created_by_event, "event_0001")

    def test_collected_ciphertext_is_removed_from_identity_lookup(self) -> None:
        ciphertext = _Ciphertext()
        python_id = id(ciphertext)
        reference = weakref.ref(ciphertext)
        observation = self.registry.observe_input(ciphertext)

        del ciphertext
        gc.collect()

        self.assertIsNone(reference())
        self.assertNotIn(python_id, self.registry._identities)
        self.assertEqual(
            self.registry.state(observation.ciphertext_id).ciphertext_id,
            observation.ciphertext_id,
        )


if __name__ == "__main__":
    unittest.main()
