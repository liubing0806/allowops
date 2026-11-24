"""Unit tests for coverage of the chart's draft-07 schema declarations."""

import unittest

from verify_matrix import undeclared_paths


class UndeclaredPathsTest(unittest.TestCase):
    def test_nonempty_array_requires_items(self):
        schema = {"properties": {"providers": {"type": "array"}}}
        self.assertEqual(list(undeclared_paths({"providers": []}, schema)), [])
        self.assertEqual(list(undeclared_paths({"providers": ["a", {}]}, schema)), ["providers[0]", "providers[1]"])

    def test_tuple_uses_schema_at_each_index(self):
        schema = {"items": [{"properties": {"host": {}}}, {"properties": {"port": {}}}]}
        values = [{"host": "local", "port": 80}, {"host": "local", "port": 80}]
        self.assertEqual(list(undeclared_paths(values, schema)), ["[0].port", "[1].host"])

    def test_tuple_overflow_checks_additional_items(self):
        values = ["first", {"name": "second", "port": 80}]
        for extra, missing in (
            ({}, ["[1]"]),
            ({"additionalItems": False}, ["[1]"]),
            ({"additionalItems": True}, []),
            ({"additionalItems": {"properties": {"name": {}}}}, ["[1].port"]),
        ):
            with self.subTest(extra=extra):
                schema = {"items": [{"type": "string"}], **extra}
                self.assertEqual(list(undeclared_paths(values, schema)), missing)

    def test_chained_local_pointers(self):
        schema = {
            "properties": {"service": {"$ref": "#/definitions/service", "properties": {"ignored": {}}}},
            "definitions": {"service": {"$ref": "#/$defs/host~1port~0pair/items/0"}},
            "$defs": {"host/port~pair": {"items": [{"properties": {"port": {}}}]}},
        }
        values = {"service": {"port": 443, "ignored": 1}}
        self.assertEqual(list(undeclared_paths(values, schema)), ["service.ignored"])

    def test_recursive_local_pointer(self):
        schema = {"properties": {"name": {}, "children": {"items": {"$ref": "#"}}}}
        values = {"name": "root", "children": [{"name": "leaf", "other": 1}]}
        self.assertEqual(list(undeclared_paths(values, schema)), ["children[0].other"])

    def test_local_named_reference(self):
        schema = {
            "properties": {"service": {"$ref": "#endpoint"}},
            "definitions": {"endpoint": {"$id": "#endpoint", "properties": {"port": {}}}},
            "default": {"$id": "#endpoint", "port": 443},
        }
        values = {"service": {"port": 443, "other": 1}}
        self.assertEqual(list(undeclared_paths(values, schema)), ["service.other"])

    def test_local_references_in_an_embedded_resource(self):
        schema = {
            "definitions": {"endpoint": {"$id": "#endpoint", "properties": {"port": {}}}},
            "properties": {
                "public": {"$ref": "#endpoint"},
                "private": {
                    "$id": "private.json",
                    "definitions": {"endpoint": {"$id": "#endpoint", "properties": {"socket": {}}}},
                    "properties": {"server": {"$ref": "#/definitions/endpoint"}},
                },
            },
        }
        values = {"public": {"port": 443}, "private": {"server": {"socket": "gateway.sock"}}}
        self.assertEqual(list(undeclared_paths(values, schema)), [])

    def test_pattern_properties_and_additional_properties(self):
        schema = {"properties": {"labels": {
            "patternProperties": {"service": {"properties": {"port": {}}}},
            "additionalProperties": {"properties": {"name": {}}},
        }}}
        values = {"labels": {"my-service": {"port": 443, "name": "internal"}, "other": {"name": "db", "port": 5432}}}
        self.assertEqual(list(undeclared_paths(values, schema)), ["labels.my-service.name", "labels.other.port"])

    def test_declarations_from_property_and_overlapping_patterns(self):
        schema = {
            "properties": {"worker-api": {"properties": {"host": {}}}},
            "patternProperties": {
                "^worker-": {"properties": {"port": {}}},
                "-api$": {"properties": {"tls": {"properties": {"enabled": {}}}}},
            },
        }
        values = {"worker-api": {"host": "local", "port": 443, "tls": {"enabled": True, "other": 1}}}
        self.assertEqual(list(undeclared_paths(values, schema)), ["worker-api.tls.other"])


if __name__ == "__main__":
    unittest.main()
