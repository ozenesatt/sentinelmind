from rag.incident_loader import load_incident
from rag.pii_masking import mask_structure
from rag.prepare_analysis import (
    get_collection,
    retrieve_context,
    build_prompt,
)


def test_rag_pipeline():
    incident = load_incident("rag/sample_incident.json")

    masked_incident, pii_mapping = mask_structure(incident)

    assert masked_incident["username"] == "[USERNAME_1]"
    assert masked_incident["src_ip"] == "[IP_1]"
    assert len(pii_mapping) == 2

    collection = get_collection()

    contexts = retrieve_context(
        collection,
        masked_incident["finding"],
    )

    assert len(contexts["cis_azure"]) > 0
    assert len(contexts["mitre"]) > 0
    assert len(contexts["kvkk"]) > 0

    prompt = build_prompt(
        masked_incident,
        contexts,
    )

    assert "UNTRUSTED DATA" in prompt
    assert "Do not invent a risk score" in prompt
    assert "[USERNAME_1]" in prompt
    assert "[IP_1]" in prompt
    assert "block_ip" in prompt
    assert "close_nsg_rule" in prompt

    print("RAG pipeline testi BASARILI")


if __name__ == "__main__":
    test_rag_pipeline()