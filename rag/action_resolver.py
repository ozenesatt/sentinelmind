import re
from typing import Any


PLACEHOLDER_RE = re.compile(
    r"\[(?:IP|USERNAME|EMAIL|TCKN)_\d+\]"
)


def resolve_placeholders(
    value: Any,
    pii_mapping: dict[str, str],
) -> Any:
    """
    Known PII placeholder'larini trusted mapping ile cozer.

    Mapping'de bulunmayan placeholder varsa fail-closed
    davranir ve ValueError firlatir.
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
        placeholders = PLACEHOLDER_RE.findall(value)

        for placeholder in placeholders:
            if placeholder not in pii_mapping:
                raise ValueError(
                    "Unknown PII placeholder rejected: "
                    f"{placeholder}"
                )

        for placeholder in placeholders:
            value = value.replace(
                placeholder,
                pii_mapping[placeholder],
            )

        return value

    return value


def resolve_action_params(
    action: dict,
    pii_mapping: dict[str, str],
) -> dict:
    """
    Recommended action params alanini trusted
    application layer'da resolve eder.

    Action type degistirilmez.
    """

    resolved = dict(action)

    resolved["params"] = resolve_placeholders(
        action.get("params", {}),
        pii_mapping,
    )

    return resolved