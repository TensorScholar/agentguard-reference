import json
import unittest
from typing import Any

from agentguard_reference import Action
from agentguard_reference.domain import canonical, digest, validate_json

PRINCIPAL = "injectivity-user"
NAME = "refund.create"
AUDIENCE = "refund-demo"


def snapshot(arguments: Any) -> str:
    return canonical({"principal": PRINCIPAL, "name": NAME, "audience": AUDIENCE,
                      "arguments": arguments})


def action_digest(arguments: Any) -> str:
    return Action.create(principal=PRINCIPAL, name=NAME, audience=AUDIENCE,
                         arguments=arguments).digest


class CanonicalisationTests(unittest.TestCase):
    def test_distinct_scalar_values_do_not_collapse(self) -> None:
        """Values that differ in type or lexical form must not share a snapshot."""
        distinct = [
            {"amount_minor": 1},
            {"amount_minor": 0},
            {"amount_minor": -1},
            {"amount_minor": 2 ** 53},
            {"amount_minor": 2 ** 53 + 1},
            {"amount_minor": "1"},
            {"amount_minor": True},
            {"amount_minor": False},
            {"amount_minor": None},
            {"amount_minor": [1]},
            {"amount_minor": {"1": None}},
            {"amount_minor": "01"},
            {"amount_minor": "+1"},
            {"amount_minor": " 1"},
            {"amount_minor": "1 "},
            {"amount_minor": "1.0"},
            {"amount_minor": ""},
        ]
        forms = [snapshot(value) for value in distinct]
        for index, left in enumerate(distinct):
            for offset, right in enumerate(distinct):
                if index == offset:
                    continue
                with self.subTest(left=left, right=right):
                    self.assertNotEqual(forms[index], forms[offset])
        self.assertEqual(len(set(forms)), len(forms))

    def test_distinct_nested_values_do_not_collapse(self) -> None:
        distinct = [
            {"a": [1, 2]},
            {"a": [2, 1]},
            {"a": [1, 2, 3]},
            {"a": [[1], [2]]},
            {"a": {"b": 1}},
            {"a": {"b": "1"}},
            {"a": {"b": [1]}},
            {"a": {"b": {"c": 1}}},
            {"a": {"bb": 1}},
        ]
        forms = [snapshot(value) for value in distinct]
        self.assertEqual(len(set(forms)), len(forms))

    def test_key_order_does_not_change_the_snapshot(self) -> None:
        """Reordering keys is the one difference that must collapse, by design."""
        self.assertEqual(snapshot({"a": 1, "b": 2}), snapshot({"b": 2, "a": 1}))
        self.assertEqual(action_digest({"amount_minor": 1, "x": 2}),
                         action_digest({"x": 2, "amount_minor": 1}))

    def test_non_ascii_has_one_canonical_escaped_form(self) -> None:
        self.assertEqual(canonical({"k": "caf\u00e9"}), '{"k":"caf\\u00e9"}')
        self.assertEqual(action_digest({"amount_minor": 1, "k": "caf\u00e9"}),
                         action_digest({"amount_minor": 1, "k": "caf\u00e9"}))

    def test_digest_is_a_pure_function_of_the_canonical_form(self) -> None:
        for arguments in ({"amount_minor": 1}, {"a": [1, {"b": None}]}, {"k": "\u00e9"}):
            with self.subTest(arguments=arguments):
                self.assertEqual(digest(arguments), digest(arguments))
                self.assertEqual(digest(arguments), digest(json.loads(canonical(arguments))))

    def test_rejected_values_never_reach_a_snapshot(self) -> None:
        """Floats and non-JSON types are refused, so they cannot alias an integer."""
        for value in (1.0, float("nan"), float("inf"), 1e300, b"1", {1: None}, object()):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    validate_json({"amount_minor": value})

    def test_float_bearing_text_is_rejected_at_construction(self) -> None:
        for text in ('{"amount_minor":1.0}', '{"amount_minor":1e2}', '{"amount_minor":NaN}',
                     '{"amount_minor":Infinity}', '{"amount_minor":true}'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    Action(PRINCIPAL, NAME, AUDIENCE, text)


if __name__ == "__main__":
    unittest.main()