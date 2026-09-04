import re
from typing import Any


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


def is_valid_tckn(value: str) -> bool:
    if not value.isdigit() or len(value) != 11:
        return False

    if value[0] == "0":
        return False

    digits = [int(x) for x in value]

    check10 = (
        (sum(digits[0:9:2]) * 7)
        - sum(digits[1:8:2])
    ) % 10

    check11 = sum(digits[:10]) % 10

    return check10 == digits[9] and check11 == digits[10]


def mask_text(text: str):
    mapping = {}
    counters = {
        "IP": 0,
        "EMAIL": 0,
        "TCKN": 0,
    }

    def replace_email(match):
        original = match.group(0)
        counters["EMAIL"] += 1
        placeholder = f"[EMAIL_{counters['EMAIL']}]"
        mapping[placeholder] = original
        return placeholder

    def replace_ip(match):
        original = match.group(0)

        parts = original.split(".")
        if any(int(part) > 255 for part in parts):
            return original

        counters["IP"] += 1
        placeholder = f"[IP_{counters['IP']}]"
        mapping[placeholder] = original
        return placeholder

    def replace_tckn(match):
        original = match.group(0)

        if not is_valid_tckn(original):
            return original

        counters["TCKN"] += 1
        placeholder = f"[TCKN_{counters['TCKN']}]"
        mapping[placeholder] = original
        return placeholder

    text = EMAIL_PATTERN.sub(replace_email, text)
    text = IP_PATTERN.sub(replace_ip, text)
    text = re.sub(r"\b\d{11}\b", replace_tckn, text)

    return text, mapping


def mask_structure(data: Any):
    mapping = {}

    if isinstance(data, dict):
        masked = {}

        for key, value in data.items():
            # Structured username alanını doğrudan maskele.
            if key.lower() == "username" and value:
                placeholder = "[USERNAME_1]"
                mapping[placeholder] = str(value)
                masked[key] = placeholder
                continue

            masked_value, child_mapping = mask_structure(value)
            masked[key] = masked_value
            mapping.update(child_mapping)

        return masked, mapping

    if isinstance(data, list):
        masked_list = []

        for item in data:
            masked_item, child_mapping = mask_structure(item)
            masked_list.append(masked_item)
            mapping.update(child_mapping)

        return masked_list, mapping

    if isinstance(data, str):
        return mask_text(data)

    return data, mapping