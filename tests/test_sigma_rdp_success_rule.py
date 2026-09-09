from pathlib import Path

import yaml


RULE_PATH = Path(
    "sigma/rules/windows_rdp_successful_logon.yml"
)


def load_rule():
    return yaml.safe_load(
        RULE_PATH.read_text(
            encoding="utf-8"
        )
    )


def get_event_id(event: dict):
    try:
        return int(
            event["data"]["win"]["system"]["eventID"]
        )
    except (KeyError, TypeError, ValueError):
        return None


def get_logon_type(event: dict):
    try:
        return int(
            event["data"]["win"]["eventdata"]["logonType"]
        )
    except (KeyError, TypeError, ValueError):
        return None


def matches_successful_rdp(
    event: dict,
    rule: dict,
) -> bool:
    selection = rule["detection"]["selection"]

    return (
        get_event_id(event)
        == int(selection["EventID"])
        and get_logon_type(event)
        == int(selection["LogonType"])
    )


def test_successful_rdp_logon_matches():
    rule = load_rule()

    event = {
        "data": {
            "win": {
                "system": {
                    "eventID": "4624"
                },
                "eventdata": {
                    "logonType": "10"
                },
            }
        }
    }

    assert matches_successful_rdp(
        event,
        rule,
    ) is True

    print(
        "4624 + LogonType 10 -> "
        "RDP SUCCESS MATCH BASARILI"
    )


def test_local_successful_logon_does_not_match():
    rule = load_rule()

    event = {
        "data": {
            "win": {
                "system": {
                    "eventID": "4624"
                },
                "eventdata": {
                    "logonType": "2"
                },
            }
        }
    }

    assert matches_successful_rdp(
        event,
        rule,
    ) is False

    print(
        "4624 + LogonType 2 -> "
        "RDP SUCCESS NO MATCH BASARILI"
    )


def test_failed_rdp_does_not_match_success_rule():
    rule = load_rule()

    event = {
        "data": {
            "win": {
                "system": {
                    "eventID": "4625"
                },
                "eventdata": {
                    "logonType": "10"
                },
            }
        }
    }

    assert matches_successful_rdp(
        event,
        rule,
    ) is False

    print(
        "4625 + LogonType 10 -> "
        "SUCCESS RULE NO MATCH BASARILI"
    )


def test_rule_has_rdp_mitre_mapping():
    rule = load_rule()

    assert "attack.t1021.001" in rule["tags"]

    print("RDP SUCCESS MITRE mapping BASARILI")


if __name__ == "__main__":
    test_successful_rdp_logon_matches()
    test_local_successful_logon_does_not_match()
    test_failed_rdp_does_not_match_success_rule()
    test_rule_has_rdp_mitre_mapping()