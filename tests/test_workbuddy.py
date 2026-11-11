import json
import pytest
from sentinel.workbuddy import configured_connectors
from sentinel.discovery import discover


def test_bound_metadata_only(tmp_path):
    folder = tmp_path / "active"
    folder.mkdir()
    (folder / "connector-states.json").write_text(
        json.dumps(
            {
                "version": 4,
                "accountIdentityKey": "FAKE_PRIVATE_ID",
                "headerOverrides": {"gmail": "FAKE_SECRET"},
                "connectors": {
                    "qq-mail": {"bound": True, "enabled": False},
                    "unused": {"bound": False, "enabled": False},
                    "example-site": {
                        "bound": True,
                        "enabled": True,
                        "ignored": "FAKE_NOT_PUBLIC",
                    },
                },
            }
        )
    )
    snapshot = discover("workbuddy", configured_connectors("active", tmp_path))
    output = snapshot.model_dump_json()
    assert "FAKE" not in output and "unused" not in output
    assert {r["service"] for r in snapshot.services} == {"qqmail", "example-site"}
    assert next(r for r in snapshot.services if r["service"] == "qqmail")[
        "reported_availability"
    ] == ["disabled"]


@pytest.mark.parametrize("profile", ["..", "a/b", "../token", ""])
def test_profile_traversal_rejected(tmp_path, profile):
    with pytest.raises(ValueError):
        configured_connectors(profile, tmp_path)


def test_future_format_is_not_guessed(tmp_path):
    folder = tmp_path / "active"
    folder.mkdir()
    (folder / "connector-states.json").write_text('{"version":99,"connectors":{}}')
    with pytest.raises(ValueError):
        configured_connectors("active", tmp_path)
