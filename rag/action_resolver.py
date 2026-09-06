from typing import Any


def resolve_placeholders(
    value: Any,
    pii_mapping: dict[str, str],
) -> Any:
    """
    AI tarafindan dondurulen action parametrelerindeki
    PII placeholder'larini trusted application layer'da
    gercek degerlerine cevirir.

    Ornek:
    [IP_1] -> 203.0.113.44
    [USERNAME_1] -> demo-user
    """

    if isinstance(value, dict):
        return {
            key: resolve_placeholders(
                child_value,
                pii_mapping,
            )
            for key, child_value in value.items()
        }

    if isinstance(value, list):
        return [
            resolve_placeholders(
                item,
                pii_mapping,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            resolve_placeholders(
                item,
                pii_mapping,
            )
            for item in value
        )

    if isinstance(value, str):
        if value in pii_mapping:
            return pii_mapping[value]

        return value

    return value


def resolve_action_params(
    action: dict,
    pii_mapping: dict[str, str],
) -> dict:
    """
    Recommended action'in params alanini resolve eder.

    Action tipi degistirilmez.
    Sadece params icindeki bilinen placeholder'lar cozulur.
    """

    resolved = dict(action)

    resolved["params"] = resolve_placeholders(
        action.get("params", {}),
        pii_mapping,
    )

    return resolved