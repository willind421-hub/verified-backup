from __future__ import annotations

import copy

import pytest

from verified_backup.config import DEFAULT_CONFIG_PATH, ConfigError, load_rules, validate_rules


def test_packaged_default_rules_load() -> None:
    rules = load_rules()
    assert DEFAULT_CONFIG_PATH.exists()
    assert rules["targets"] == [
        {"name": "source_root", "path": ".", "include": ["**/*"], "exclude": []}
    ]
    assert rules["exclude"]["skip_symlinks"] is True


@pytest.mark.parametrize("bad_path", ["..", "../outside", "data/../../x", "/etc", "C:/x", "C:x", "\\x"])
def test_target_paths_must_stay_inside_source_root(bad_path: str) -> None:
    rules = copy.deepcopy(load_rules())
    rules["targets"][0]["path"] = bad_path
    with pytest.raises(ConfigError):
        validate_rules(rules)


def test_unknown_schema_version_is_rejected() -> None:
    rules = copy.deepcopy(load_rules())
    rules["schema_version"] = "something-else/v1"
    with pytest.raises(ConfigError):
        validate_rules(rules)
