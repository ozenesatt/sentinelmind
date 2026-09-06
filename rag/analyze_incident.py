import argparse

from rag.incident_loader import load_incident
from rag.pii_masking import mask_structure
from rag.prepare_analysis import (
    get_collection,
    retrieve_context,
    build_prompt,
)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "incident_file",
        help="Analiz edilecek incident JSON dosyasi",
    )

    args = parser.parse_args()

    print("Incident okunuyor...")
    incident = load_incident(args.incident_file)

    print("PII maskeleme uygulaniyor...")
    masked_incident, pii_mapping = mask_structure(incident)

    print(f"Maskelenen alan sayisi: {len(pii_mapping)}")

    finding = masked_incident.get("finding", "")

    if not finding:
        raise ValueError(
            "Incident icinde 'finding' alani bulunamadi."
        )

    print("RAG context getiriliyor...")
    collection = get_collection()

    contexts = retrieve_context(
        collection,
        finding,
    )

    print("Prompt olusturuluyor...")
    prompt = build_prompt(
        masked_incident,
        contexts,
    )

    print()
    print("=" * 70)
    print("LOCAL ANALYSIS PIPELINE BASARILI")
    print("=" * 70)

    print(f"Incident ID: {incident['incident_id']}")
    print(f"Risk Score: {incident['risk_score']}")
    print(f"Severity: {incident['severity']}")
    print(f"PII Masked Fields: {len(pii_mapping)}")

    print()
    print("RAG sonuclari:")

    for source in ["cis_azure", "mitre", "kvkk"]:
        print(f"- {source}: {len(contexts[source])} context")

    print()
    print("Prompt LLM'e gonderilmeye hazir.")
    print("Gercek PII mapping ekrana veya loglara yazilmadi.")


if __name__ == "__main__":
    main()