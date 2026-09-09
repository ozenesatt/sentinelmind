from pathlib import Path

import yaml


RULE_PATH = Path(
    "sigma/rules/windows_rdp_failed_logon.yml"
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


def matches_rdp_failed_logon(
    event: dict,
    rule: dict,
) -> bool:
    selection = rule["detection"]["selection"]

    expected_event_id = int(
        selection["EventID"]
    )

    expected_logon_type = int(
        selection["LogonType"]
    )

    return (
        get_event_id(event) == expected_event_id
        and get_logon_type(event) == expected_logon_type
    )


def test_failed_rdp_logon_matches():
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

    assert matches_rdp_failed_logon(
        event,
        rule,
    ) is True

    print(
        "4625 + LogonType 10 -> RDP Sigma MATCH BASARILI"
    )


def test_normal_failed_logon_does_not_match_rdp():
    rule = load_rule()

    event = {
        "data": {
            "win": {
                "system": {
                    "eventID": "4625"
                },
                "eventdata": {
                    "logonType": "3"
                },
            }
        }
    }

    assert matches_rdp_failed_logon(
        event,
        rule,
    ) is False

    print(
        "4625 + LogonType 3 -> RDP Sigma NO MATCH BASARILI"
    )


def test_rdp_rule_has_mitre_mapping():
    rule = load_rule()

    assert "attack.t1110" in rule["tags"]
    assert "attack.t1021.001" in rule["tags"]

    print(
        "RDP Sigma MITRE mapping BASARILI"
    )


if __name__ == "__main__":
    test_failed_rdp_logon_matches()
    test_normal_failed_logon_does_not_match_rdp()
    test_rdp_rule_has_mitre_mapping()