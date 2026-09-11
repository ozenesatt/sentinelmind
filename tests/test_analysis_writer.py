from rag.analysis_writer import validate_incident_id


def test_valid_incident_uuid():
    incident_id = (
        "550e8400-e29b-41d4-a716-446655440000"
    )

    result = validate_incident_id(incident_id)

    assert str(result) == incident_id

    print("Valid incident UUID testi BASARILI")


def test_invalid_incident_uuid_is_rejected():
    incident_id = "demo-prowler-001"

    try:
        validate_incident_id(incident_id)

    except ValueError:
        print("Invalid incident UUID reddedildi")
        return

    raise AssertionError(
        "Invalid incident UUID kabul edildi!"
    )


if __name__ == "__main__":
    test_valid_incident_uuid()
    test_invalid_incident_uuid_is_rejected()