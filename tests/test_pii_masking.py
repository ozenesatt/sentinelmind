from rag.pii_masking import mask_text, mask_structure, is_valid_tckn


def test_basic_pii_masking():
    text = (
        "User test@example.com connected from 203.0.113.44."
    )

    masked, mapping = mask_text(text)

    assert "[EMAIL_1]" in masked
    assert "[IP_1]" in masked

    assert mapping["[EMAIL_1]"] == "test@example.com"
    assert mapping["[IP_1]"] == "203.0.113.44"

    print("Temel PII masking BASARILI")


def test_invalid_ip_not_masked():
    text = "Invalid IP: 999.999.999.999"

    masked, mapping = mask_text(text)

    assert "999.999.999.999" in masked
    assert "[IP_1]" not in masked
    assert len(mapping) == 0

    print("Gecersiz IP reddedildi")


def test_username_masking():
    data = {
        "username": "demo-user",
        "message": "Login failed",
    }

    masked, mapping = mask_structure(data)

    assert masked["username"] == "[USERNAME_1]"
    assert mapping["[USERNAME_1]"] == "demo-user"

    print("Username masking BASARILI")


def test_tckn_validation():
    valid_tckn = "10000000146"
    invalid_tckn = "12345678901"

    assert is_valid_tckn(valid_tckn) is True
    assert is_valid_tckn(invalid_tckn) is False

    masked, mapping = mask_text(
        f"TCKN: {valid_tckn}"
    )

    assert "[TCKN_1]" in masked
    assert mapping["[TCKN_1]"] == valid_tckn

    print("TCKN masking BASARILI")


if __name__ == "__main__":
    test_basic_pii_masking()
    test_invalid_ip_not_masked()
    test_username_masking()
    test_tckn_validation()