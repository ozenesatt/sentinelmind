from eval.scoring_v2 import (
    V2_THRESHOLD,
    V2_VERSION,
    contextual_bonus,
)


def test_v2_version_is_frozen():
    assert V2_VERSION == "1.0"
    assert V2_THRESHOLD == 60

    print("Scoring V2 version freeze BASARILI")


def test_keyvault_bonus():
    scored = {
        "event_code": "keyvault_logging_enabled",
    }

    bonus, reasons = contextual_bonus(
        scored
    )

    assert bonus == 15
    assert (
        "keyvault-sensitive-service +15"
        in reasons
    )

    print("V2 Key Vault bonus BASARILI")


def test_network_telemetry_bonus():
    scored = {
        "event_code":
            "network_flow_log_captured_sent",
    }

    bonus, reasons = contextual_bonus(
        scored
    )

    assert bonus == 10
    assert "network-telemetry +10" in reasons

    print("V2 network telemetry bonus BASARILI")


def test_private_endpoint_bonus():
    scored = {
        "event_code":
            "storage_ensure_private_endpoints_in_storage_accounts",
    }

    bonus, reasons = contextual_bonus(
        scored
    )

    assert bonus == 10
    assert (
        "private-endpoint-boundary +10"
        in reasons
    )

    print("V2 private endpoint bonus BASARILI")


def test_secure_transfer_bonus():
    scored = {
        "event_code":
            "storage_secure_transfer_required_is_enabled",
    }

    bonus, reasons = contextual_bonus(
        scored
    )

    assert bonus == 5
    assert "secure-transport +5" in reasons

    print("V2 secure transport bonus BASARILI")


if __name__ == "__main__":
    test_v2_version_is_frozen()
    test_keyvault_bonus()
    test_network_telemetry_bonus()
    test_private_endpoint_bonus()
    test_secure_transfer_bonus()