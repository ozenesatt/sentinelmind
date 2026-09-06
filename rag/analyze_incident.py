import argparse

from rag.action_resolver import resolve_action_params
from rag.analysis_binding import bind_authoritative_fields
from rag.azure_ai import analyze_with_azure
from rag.incident_loader import load_incident
from rag.pii_masking import mask_structure
from rag.prepare_analysis import (
    build_prompt,
    get_collection,
    retrieve_context,
)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "incident_file",
        help="Analiz edilecek incident JSON dosyasi",
    )

    parser.add_argument(
        "--azure",
        action="store_true",
        help="Hazirlanan promptu gercek Azure OpenAI modeline gonder",
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
        print(
            f"- {source}: "
            f"{len(contexts[source])} context"
        )

    print()
    print(
        "Gercek PII mapping ekrana veya loglara yazilmadi."
    )

    if not args.azure:
        print()
        print(
            "Prompt LLM'e gonderilmeye hazir. "
            "Gercek Azure analizi icin --azure kullan."
        )
        return

    print()
    print("Azure OpenAI structured analysis baslatiliyor...")

    model_analysis = analyze_with_azure(prompt)

    print("Authoritative alanlar incident verisiyle bind ediliyor...")

    final_analysis = bind_authoritative_fields(
        model_analysis,
        incident,
    )

    print(
        "Action parametreleri trusted application layer'da "
        "resolve ediliyor..."
    )

    resolved_actions = []

    for action in final_analysis.recommended_actions:
        resolved_action = resolve_action_params(
            action.model_dump(),
            pii_mapping,
        )

        resolved_actions.append(resolved_action)

    print()
    print("=" * 70)
    print("AZURE STRUCTURED ANALYSIS BASARILI")
    print("=" * 70)

    print(
        f"Incident ID: {final_analysis.incident_id}"
    )
    print(
        f"Severity: {final_analysis.severity}"
    )
    print(
        f"Generated At: {final_analysis.generated_at}"
    )
    print(
        f"Title: {final_analysis.title_tr}"
    )

    print(
        "MITRE Techniques: "
        f"{final_analysis.mitre_techniques}"
    )

    print(
        "Recommended Action Count: "
        f"{len(final_analysis.recommended_actions)}"
    )

    print(
        "Resolved Action Count: "
        f"{len(resolved_actions)}"
    )

    print()
    print(
        "PII degerleri ve resolved action parametreleri "
        "guvenlik nedeniyle ekrana yazilmadi."
    )

    print()
    print(
        "Final AI analysis structured output olarak "
        "dogrulandi."
    )


if __name__ == "__main__":
    main()