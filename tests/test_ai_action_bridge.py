import copy

import pytest

from engine.ai_action_bridge import (
    build_close_nsg_plan,
    parse_nsg_resource_id,
)


INCIDENT_ID = "f49d731e-c4c4-4778-84a6-d26a4df663bd"
ANALYSIS_ID = "eedcfb7c-5320-4d3a-a0bf-3d3380dd96ca"

RESOURCE_ID = (
    "/subscriptions/"
    "d6bbe32e-08e3-4513-aea3-0f36665669c7/"
    "resourceGroups/sentinelmind-rg/"
    "providers/Microsoft.Network/"
    "networkSecurityGroups/sentinelmind-soc-nsg"
)


def make_data():
    incident = {
        "id": INCIDENT_ID,
        "event_ids": [31],
        "risk_score": 70,
        "severity": "high",
        "status": "new",
    }

    analysis = {
        "id": ANALYSIS_ID,
        "incident_id": INCIDENT_ID,
        "pii_masked": True,
        "payload": {
            "incident_id": INCIDENT_ID,
            "recommended_actions": [
                {
                    "action_type": "close_nsg_rule",
                    "params": {
                        "resource_id": RESOURCE_ID,
                        "rule_name":
                            "DEMO-Insecure-SSH-Any",
                    },
                }
            ],
        },
    }

    events = [
        {
            "id": 31,
            "source": "prowler",
            "resource_id": RESOURCE_ID,
            "raw": {
                "resources": [
                    {
                        "uid": RESOURCE_ID,
                        "type":
                            "microsoft.network/"
                            "networksecuritygroups",
                        "data": {
                            "metadata": {
                                "security_rules": [
                                    {
                                        "name":
                                            "DEMO-Insecure-SSH-Any",
                                        "access": "Allow",
                                        "direction": "Inbound",
                                        "protocol": "Tcp",
                                        "source_address_prefix":
                                            "*",
                                        "destination_port_range":
                                            "22",
                                    }
                                ]
                            }
                        },
                    }
                ]
            },
        }
    ]

    return incident, analysis, events


def test_valid_close_nsg_plan():
    incident, analysis, events = make_data()

    plan = build_close_nsg_plan(
        incident,
        analysis,
        events,
    )

    assert plan["incident_id"] == INCIDENT_ID
    assert plan["analysis_id"] == ANALYSIS_ID
    assert plan["source_event_id"] == 31
    assert plan["action_type"] == "close_nsg_rule"

    assert plan["params"]["resource_group"] == (
        "sentinelmind-rg"
    )

    assert plan["params"]["nsg_name"] == (
        "sentinelmind-soc-nsg"
    )

    assert plan["params"]["rule_name"] == (
        "DEMO-Insecure-SSH-Any"
    )


def test_ai_resource_mismatch_rejected():
    incident, analysis, events = make_data()

    analysis = copy.deepcopy(analysis)
    analysis["payload"]["recommended_actions"][0][
        "params"
    ]["resource_id"] = RESOURCE_ID + "-wrong"

    with pytest.raises(
        ValueError,
        match="trusted Prowler",
    ):
        build_close_nsg_plan(
            incident,
            analysis,
            events,
        )


def test_wrong_rule_name_rejected():
    incident, analysis, events = make_data()

    analysis = copy.deepcopy(analysis)
    analysis["payload"]["recommended_actions"][0][
        "params"
    ]["rule_name"] = "Wrong-Rule"

    with pytest.raises(
        ValueError,
        match="trusted Prowler",
    ):
        build_close_nsg_plan(
            incident,
            analysis,
            events,
        )


def test_private_source_rejected():
    incident, analysis, events = make_data()

    events = copy.deepcopy(events)

    events[0]["raw"]["resources"][0]["data"][
        "metadata"
    ]["security_rules"][0][
        "source_address_prefix"
    ] = "10.0.0.0/24"

    with pytest.raises(
        ValueError,
        match="Internet kaynakli SSH",
    ):
        build_close_nsg_plan(
            incident,
            analysis,
            events,
        )


def test_non_ssh_port_rejected():
    incident, analysis, events = make_data()

    events = copy.deepcopy(events)

    events[0]["raw"]["resources"][0]["data"][
        "metadata"
    ]["security_rules"][0][
        "destination_port_range"
    ] = "443"

    with pytest.raises(
        ValueError,
        match="SSH/TCP 22",
    ):
        build_close_nsg_plan(
            incident,
            analysis,
            events,
        )


def test_unmasked_analysis_rejected():
    incident, analysis, events = make_data()

    analysis = copy.deepcopy(analysis)
    analysis["pii_masked"] = False

    with pytest.raises(
        ValueError,
        match="pii_masked=True",
    ):
        build_close_nsg_plan(
            incident,
            analysis,
            events,
        )


def test_invalid_nsg_resource_id_rejected():
    with pytest.raises(
        ValueError,
        match="Azure NSG",
    ):
        parse_nsg_resource_id(
            "/subscriptions/demo/providers/"
            "Microsoft.Compute/virtualMachines/vm1"
        )
