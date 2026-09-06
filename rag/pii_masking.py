import re
from typing import Any


EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

TCKN_RE = re.compile(
    r"\b\d{11}\b"
)


def is_valid_ip(value: str) -> bool:
    parts = value.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def is_valid_tckn(value: str) -> bool:
    if not value.isdigit() or len(value) != 11:
        return False

    if value[0] == "0":
        return False

    digits = [int(x) for x in value]

    digit_10 = (
        7 * sum(digits[0:9:2])
        - sum(digits[1:8:2])
    ) % 10

    if digit_10 != digits[9]:
        return False

    digit_11 = sum(digits[:10]) % 10

    return digit_11 == digits[10]


class _Masker:
    def __init__(self):
        self.mapping: dict[str, str] = {}
        self.counters = {
            "EMAIL": 0,
            "IP": 0,
            "TCKN": 0,
            "USERNAME": 0,
        }

        # Aynı gerçek değer tekrar görülürse
        # aynı placeholder kullanılabilsin.
        self.reverse_mapping: dict[tuple[str, str], str] = {}

    def _placeholder(self, category: str, value: str) -> str:
        key = (category, value)

        if key in self.reverse_mapping:
            return self.reverse_mapping[key]

        self.counters[category] += 1

        placeholder = (
            f"[{category}_{self.counters[category]}]"
        )

        self.mapping[placeholder] = value
        self.reverse_mapping[key] = placeholder

        return placeholder

    def mask_text(self, text: str) -> str:
        def replace_email(match):
            value = match.group(0)
            return self._placeholder("EMAIL", value)

        text = EMAIL_RE.sub(replace_email, text)

        def replace_ip(match):
            value = match.group(0)

            if not is_valid_ip(value):
                return value

            return self._placeholder("IP", value)

        text = IP_RE.sub(replace_ip, text)

        def replace_tckn(match):
            value = match.group(0)

            if not is_valid_tckn(value):
                return value

            return self._placeholder("TCKN", value)

        text = TCKN_RE.sub(replace_tckn, text)

        return text

    def mask_structure(self, value: Any, key: str | None = None):
        if isinstance(value, dict):
            return {
                child_key: self.mask_structure(
                    child_value,
                    key=child_key,
                )
                for child_key, child_value in value.items()
            }

        if isinstance(value, list):
            return [
                self.mask_structure(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return tuple(
                self.mask_structure(item)
                for item in value
            )

        if isinstance(value, str):
            # username alanını anahtar üzerinden de koruyoruz.
            if key and key.lower() in {
                "username",
                "user_name",
                "user",
            }:
                return self._placeholder(
                    "USERNAME",
                    value,
                )

            return self.mask_text(value)

        return value


def mask_text(text: str):
    masker = _Masker()
    masked = masker.mask_text(text)

    return masked, masker.mapping


def mask_structure(data: Any):
    masker = _Masker()
    masked = masker.mask_structure(data)

    return masked, masker.mapping