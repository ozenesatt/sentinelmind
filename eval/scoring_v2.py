from engine.filter_engine import score_finding


V2_VERSION = "1.0"

V2_THRESHOLD = 60


def contextual_bonus(
    scored: dict,
) -> tuple[int, list[str]]:
    """
    SentinelMind Experimental Scoring V2.

    Bu kurallar tuning dataset uzerindeki hata analizi
    sonucunda olusturuldu.

    Holdout validation basladiktan sonra bu kurallar
    degistirilmemelidir.
    """

    code = scored["event_code"]

    bonus = 0
    reasons = []

    if code.startswith("keyvault_"):
        bonus += 15
        reasons.append(
            "keyvault-sensitive-service +15"
        )

    if code in {
        "network_flow_log_captured_sent",
        "network_watcher_enabled",
    }:
        bonus += 10
        reasons.append(
            "network-telemetry +10"
        )

    if (
        code
        == "storage_ensure_private_endpoints_in_storage_accounts"
    ):
        bonus += 10
        reasons.append(
            "private-endpoint-boundary +10"
        )

    if (
        code
        == "storage_secure_transfer_required_is_enabled"
    ):
        bonus += 5
        reasons.append(
            "secure-transport +5"
        )

    return bonus, reasons


def score_finding_v2(
    finding: dict,
) -> dict:
    baseline = score_finding(finding)

    bonus, reasons = contextual_bonus(
        baseline
    )

    v2_score = min(
        baseline["score"] + bonus,
        100,
    )

    return {
        **baseline,
        "baseline_score": baseline["score"],
        "v2_score": v2_score,
        "v2_bonus": bonus,
        "v2_reasons": reasons,
        "v2_version": V2_VERSION,
    }