from pathlib import Path

import yaml


RULE_PATH = Path(
    "sigma/rules/windows_failed_logon_4625.yml"
)


def load_rule():
    return yaml.safe_load(
        RULE_PATH.read_text(
            encoding="utf-8"
        )
    )


def get_event_id(event: dict):
    """
    Hem generic Windows EventID hem de
    Wazuh nested event yapisini destekler.
    """

    if "EventID" in event:
        return int(event["EventID"])

    try:
        return int(
            event["data"]["win"]["system"]["eventID"]
        )
    except (KeyError, TypeError, ValueError):
        return None


def matches_rule(event: dict, rule: dict) -> bool:
    expected_event_id = int(
        rule["detection"]["selection"]["EventID"]
    )

    actual_event_id = get_event_id(event)

    return actual_event_id == expected_event_id


def test_wazuh_4625_matches_sigma_rule():
    rule = load_rule()

    event = {
        "data": {
            "win": {
                "system": {
                    "eventID": "4625"
                }
            }
        }
    }

    assert matches_rule(event, rule) is True

    print("Wazuh 4625 -> Sigma MATCH BASARILI")


def test_windows_4624_does_not_match():
    rule = load_rule()

    event = {
        "data": {
            "win": {
                "system": {
                    "eventID": "4624"
                }
            }
        }
    }

    assert matches_rule(event, rule) is False

    print("Windows 4624 -> Sigma NO MATCH BASARILI")


def test_rule_has_mitre_mapping():
    rule = load_rule()

    assert "attack.t1110" in rule["tags"]

    print("Sigma MITRE T1110 mapping BASARILI")


if __name__ == "__main__":
    test_wazuh_4625_matches_sigma_rule()
    test_windows_4624_does_not_match()
    test_rule_has_mitre_mapping()