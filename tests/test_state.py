"""Tests for recorder-owned copies of trace data."""

from __future__ import annotations

import json
import unittest
from collections import ChainMap
from types import MappingProxyType

from cipherscope.compatibility import CompatibilityRegistry
from cipherscope.recorder import EventRecorder
from cipherscope.state import copy_mapping


class StateCopyTests(unittest.TestCase):
    def test_nested_mapping_types_are_copied_to_plain_dicts(self) -> None:
        values = [1, 2]
        nested = ChainMap({"values": values})
        source = MappingProxyType({"nested": nested})

        copied = copy_mapping(source)
        values.append(3)

        self.assertEqual(copied, {"nested": {"values": [1, 2]}})
        self.assertIsInstance(copied["nested"], dict)
        json.dumps(copied)

    def test_recorder_does_not_retain_nested_mapping_references(self) -> None:
        values = ["before"]
        details = MappingProxyType({"values": values})
        event = MappingProxyType(
            {
                "sequence": 1,
                "kind": "annotation",
                "details": details,
                "missing": [],
            }
        )
        recorder = EventRecorder(compatibility=CompatibilityRegistry())

        recorder.record_event(event)
        values.append("after")
        trace = recorder.to_trace(context={})

        self.assertEqual(trace["events"][0]["details"], {"values": ["before"]})
        json.dumps(trace)


if __name__ == "__main__":
    unittest.main()
