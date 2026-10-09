"""Offline tests for co_v4.codex_inventory.parse_inventory."""

import copy
import unittest

from co_v4.adapters.codex import NativeError
from co_v4.codex_host import FEATURES_01601
from co_v4.codex_inventory import parse_inventory


def _valid_config(**overrides):
    config = {
        "model": "gpt-5.3-codex",
        "approval_policy": "never",
        "sandbox_mode": "workspace-write",
        "service_tier": "default",
        "mcp_servers": {},
        "notify": [],
        "web_search": "disabled",
        "features": {name: False for name in FEATURES_01601},
        "shell_environment_policy": {
            "inherit": "none",
            "set": {},
            "include_only": [],
            "extra_policy_field": "allowed",
        },
        "plugins": {},
        "hooks": {},
        "unrelated_top_level": {"nested": [1, 2, 3]},
    }
    config.update(overrides)
    return config


class ParseInventorySuccessTests(unittest.TestCase):
    def test_collects_all_mcp_names_regardless_of_enabled(self):
        config = _valid_config(mcp_servers={
            "zeta": {"enabled": True, "command": "run-me"},
            "alpha": {"enabled": False},
            "mid": {},
        })
        result = parse_inventory(config)
        self.assertEqual(len(result), 2)
        self.assertEqual(set(result),
                         {"disabled_mcp_servers", "cleared_environment_keys"})
        self.assertIs(type(result["disabled_mcp_servers"]), tuple)
        self.assertIs(type(result["cleared_environment_keys"]), tuple)
        self.assertEqual(result["disabled_mcp_servers"],
                         ("alpha", "mid", "zeta"))
        self.assertEqual(result["cleared_environment_keys"], ())

    def test_set_values_stay_opaque(self):
        class Opaque:
            def __repr__(self):
                raise AssertionError("set value was inspected")
            __str__ = __repr__

        config = _valid_config()
        config["shell_environment_policy"]["set"] = {
            "PATH": Opaque(),
            "SECRET_TOKEN": Opaque(),
        }
        result = parse_inventory(config)
        self.assertEqual(result["cleared_environment_keys"],
                         ("PATH", "SECRET_TOKEN"))

    def test_sorted_outputs(self):
        config = _valid_config(mcp_servers={"z": {}, "a": {}, "m": {}})
        config["shell_environment_policy"]["set"] = {
            "Z": "inherited", "A": "inherited", "M": "inherited"}
        result = parse_inventory(config)
        self.assertEqual(result["disabled_mcp_servers"], ("a", "m", "z"))
        self.assertEqual(result["cleared_environment_keys"], ("A", "M", "Z"))

    def test_empty_missing_none_inventory(self):
        expected = {"disabled_mcp_servers": (),
                    "cleared_environment_keys": ()}
        self.assertEqual(parse_inventory(_valid_config()), expected)
        config = _valid_config(mcp_servers=None)
        config["shell_environment_policy"]["set"] = None
        self.assertEqual(parse_inventory(config), expected)
        del config["mcp_servers"]
        del config["shell_environment_policy"]["set"]
        self.assertEqual(parse_inventory(config), expected)

    def test_extra_feature_and_policy_keys_allowed(self):
        config = _valid_config()
        config["features"]["some_future_flag"] = True
        parse_inventory(config)

    def test_boundaries_accepted(self):
        config = _valid_config()
        config["mcp_servers"] = {f"s{i:02d}": {} for i in range(64)}
        config["shell_environment_policy"]["set"] = {
            f"K{i:0127d}": "inherited" for i in range(128)}
        result = parse_inventory(config)
        self.assertEqual(len(result["disabled_mcp_servers"]), 64)
        self.assertEqual(len(result["cleared_environment_keys"]), 128)
        config["mcp_servers"] = {"n" * 128: {}}
        config["shell_environment_policy"]["set"] = {"K" * 128: "v"}
        parse_inventory(config)

    def test_input_not_mutated(self):
        config = _valid_config(mcp_servers={"b": {}, "a": {}})
        config["shell_environment_policy"]["set"] = {"B": "keep", "A": "keep"}
        before = copy.deepcopy(config)
        result = parse_inventory(config)
        self.assertEqual(config, before)
        self.assertIsNot(result, config)


class ParseInventoryRefusalTests(unittest.TestCase):
    def _assert_invalid(self, config):
        with self.assertRaises(NativeError) as cm:
            parse_inventory(config)
        self.assertEqual(str(cm.exception), "native_inventory_invalid")
        self.assertIsNone(cm.exception.__cause__)

    def test_config_not_exact_dict(self):
        class Sub(dict):
            pass
        for bad in (None, [], (), "", 0, False, Sub()):
            with self.subTest(config=repr(bad)):
                self._assert_invalid(bad)

    def test_mcp_servers_wrong_types(self):
        for bad in ([], (), "", 0, False):
            with self.subTest(mcp_servers=repr(bad)):
                self._assert_invalid(_valid_config(mcp_servers=bad))

    def test_mcp_bounds_and_names(self):
        servers = {f"s{i:02d}": {} for i in range(65)}
        self._assert_invalid(_valid_config(mcp_servers=servers))
        for name in ("has.dot", "has space", 'quo"te', "back\\slash",
                     "non-ascii-é", "", "a" * 129):
            with self.subTest(name=name):
                self._assert_invalid(_valid_config(mcp_servers={name: {}}))

    def test_mcp_entry_wrong_types(self):
        for entry in ([], (), "", 0, False, None):
            with self.subTest(entry=repr(entry)):
                self._assert_invalid(
                    _valid_config(mcp_servers={"ok": entry}))

    def test_policy_required_exact_dict(self):
        config = _valid_config()
        del config["shell_environment_policy"]
        self._assert_invalid(config)
        for bad in (None, [], (), "", 0, False):
            with self.subTest(policy=repr(bad)):
                config = _valid_config()
                config["shell_environment_policy"] = bad
                self._assert_invalid(config)

    def test_set_wrong_types_bounds_names(self):
        for bad in ([], (), "", 0, False):
            with self.subTest(set_value=repr(bad)):
                config = _valid_config()
                config["shell_environment_policy"]["set"] = bad
                self._assert_invalid(config)
        config = _valid_config()
        config["shell_environment_policy"]["set"] = {
            f"K{i}": "x" for i in range(129)}
        self._assert_invalid(config)
        for key in ("9LEADING", "HAS.DOT", "HAS-DASH", "HAS SPACE",
                    "non_ascii_é", "", "K" * 129):
            with self.subTest(key=key):
                config = _valid_config()
                config["shell_environment_policy"]["set"] = {key: "x"}
                self._assert_invalid(config)

    def test_features_required_and_all_disabled(self):
        for bad in (None, [], (), "", 0, False):
            with self.subTest(features=repr(bad)):
                self._assert_invalid(_valid_config(features=bad))
        missing = object()
        for name in FEATURES_01601:
            for bad_value in (missing, True, 0, 1, None):
                features = {n: False for n in FEATURES_01601}
                if bad_value is missing:
                    del features[name]
                else:
                    features[name] = bad_value
                label = "missing" if bad_value is missing else bad_value
                with self.subTest(feature=name, value=label):
                    self._assert_invalid(_valid_config(features=features))

    def test_web_search_and_notify(self):
        for bad in ("enabled", "Disabled", "", None, [], 0, False):
            with self.subTest(web_search=repr(bad)):
                self._assert_invalid(_valid_config(web_search=bad))
        config = _valid_config()
        del config["web_search"]
        self._assert_invalid(config)
        for bad in ("cmd", 0, False, {}, (), ["echo", "hi"]):
            with self.subTest(notify=repr(bad)):
                self._assert_invalid(_valid_config(notify=bad))
        config = _valid_config()
        del config["notify"]
        parse_inventory(config)
        config["notify"] = None
        parse_inventory(config)

    def test_inherit_and_include_only(self):
        for bad in ("all", "core", "None", "", None, 0, False):
            with self.subTest(inherit=repr(bad)):
                config = _valid_config()
                config["shell_environment_policy"]["inherit"] = bad
                self._assert_invalid(config)
        for bad in (["A"], "A", 0, False, (), None):
            with self.subTest(include_only=repr(bad)):
                config = _valid_config()
                config["shell_environment_policy"]["include_only"] = bad
                self._assert_invalid(config)
        config = _valid_config()
        del config["shell_environment_policy"]["include_only"]
        self._assert_invalid(config)

    def test_error_text_never_leaks_payload(self):
        config = _valid_config(
            mcp_servers={"bad name": {"token": "S3CR3T-VALUE"}})
        config["shell_environment_policy"]["set"] = {
            "VALID_KEY": "S3CR3T-VALUE"}
        with self.assertRaises(NativeError) as cm:
            parse_inventory(config)
        self.assertEqual(str(cm.exception), "native_inventory_invalid")
        self.assertNotIn("S3CR3T", str(cm.exception))
        self.assertNotIn("S3CR3T", repr(cm.exception))


if __name__ == "__main__":
    unittest.main()
