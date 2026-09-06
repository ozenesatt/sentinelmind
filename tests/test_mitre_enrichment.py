def resolve_mitre_techniques(
    source_mitre_ids: list[str],
    rag_mitre_ids: list[str],
) -> dict:
    """
    Source event icinde MITRE ID varsa source ground truth korunur.
    Source MITRE yoksa RAG sonuclari enrichment olarak kullanilir.
    """

    if source_mitre_ids:
        return {
            "techniques": source_mitre_ids,
            "source": "event",
            "is_ground_truth": True,
        }

    return {
        "techniques": rag_mitre_ids,
        "source": "rag_enrichment",
        "is_ground_truth": False,
    }


def test_source_mitre_is_preserved():
    result = resolve_mitre_techniques(
        source_mitre_ids=["T1110"],
        rag_mitre_ids=["T1530", "T1619"],
    )

    assert result["techniques"] == ["T1110"]
    assert result["source"] == "event"
    assert result["is_ground_truth"] is True

    print("Source MITRE koruma testi BASARILI")


def test_rag_mitre_is_only_enrichment():
    result = resolve_mitre_techniques(
        source_mitre_ids=[],
        rag_mitre_ids=["T1530", "T1619"],
    )

    assert result["techniques"] == ["T1530", "T1619"]
    assert result["source"] == "rag_enrichment"
    assert result["is_ground_truth"] is False

    print("RAG MITRE enrichment testi BASARILI")


if __name__ == "__main__":
    test_source_mitre_is_preserved()
    test_rag_mitre_is_only_enrichment()
    