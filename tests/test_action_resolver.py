from rag.action_resolver import resolve_action_params


def test_block_ip_placeholder_is_resolved():
    pii_mapping = {
        "[IP_1]": "203.0.113.44",
        "[USERNAME_1]": "demo-user",
    }

    action = {
        "action_type": "block_ip",
        "params": {
            "ip": "[IP_1]",
        },
        "rationale_tr": "Kaynak IP engellenebilir.",
    }

    resolved = resolve_action_params(
        action,
        pii_mapping,
    )

    assert resolved["action_type"] == "block_ip"
    assert resolved["params"]["ip"] == "203.0.113.44"

    print("block_ip placeholder resolve BASARILI")


def test_disable_user_placeholder_is_resolved():
    pii_mapping = {
        "[USERNAME_1]": "demo-user",
    }

    action = {
        "action_type": "disable_user",
        "params": {
            "username": "[USERNAME_1]",
        },
        "rationale_tr": "Kullanici hesabi incelenebilir.",
    }

    resolved = resolve_action_params(
        action,
        pii_mapping,
    )

    assert resolved["action_type"] == "disable_user"
    assert resolved["params"]["username"] == "demo-user"

    print("disable_user placeholder resolve BASARILI")


def test_unknown_placeholder_is_not_resolved():
    pii_mapping = {
        "[IP_1]": "203.0.113.44",
    }

    action = {
        "action_type": "block_ip",
        "params": {
            "ip": "[IP_999]",
        },
        "rationale_tr": "Test",
    }

    resolved = resolve_action_params(
        action,
        pii_mapping,
    )

    assert resolved["params"]["ip"] == "[IP_999]"

    print("Unknown placeholder koruma testi BASARILI")


if __name__ == "__main__":
    test_block_ip_placeholder_is_resolved()
    test_disable_user_placeholder_is_resolved()
    test_unknown_placeholder_is_not_resolved()