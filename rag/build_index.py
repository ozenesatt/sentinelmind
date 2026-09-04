from pathlib import Path
import json

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from pypdf import PdfReader


BASE_DIR = Path(__file__).resolve().parent
CORPUS_DIR = BASE_DIR / "corpus"
CHROMA_DIR = BASE_DIR / "chroma_db"


def read_pdf(path: Path) -> str:
    reader = PdfReader(path)
    pages = []

    for page in reader.pages:
        text = page.extract_text() or ""
        text = text.strip()

        if text:
            pages.append(text)

    return "\n\n".join(pages)


def read_mitre_json(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = []

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")

        external_id = ""

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id", "")
                break

        if not external_id:
            continue

        techniques.append(
            {
                "text": (
                    f"MITRE Technique: {external_id}\n"
                    f"Name: {name}\n"
                    f"Description: {description}"
                ),
                "technique_id": external_id,
                "technique_name": name,
            }
        )

    return techniques


def chunk_text(text: str, chunk_size: int = 1200, overlap: int = 200) -> list[str]:
    chunks = []

    start = 0

    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        start += chunk_size - overlap

    return chunks


def add_text_source(
    collection,
    source_name: str,
    text: str,
):
    chunks = chunk_text(text)

    documents = []
    metadatas = []
    ids = []

    for i, chunk in enumerate(chunks):
        documents.append(chunk)

        metadatas.append(
            {
                "source": source_name,
                "chunk_index": i,
            }
        )

        ids.append(f"{source_name}-{i}")

    collection.add(
        documents=documents,
        metadatas=metadatas,
        ids=ids,
    )

    return len(chunks)


def add_mitre_source(collection, techniques: list[dict]):
    documents = []
    metadatas = []
    ids = []

    for i, item in enumerate(techniques):
        documents.append(item["text"])

        metadatas.append(
            {
                "source": "mitre",
                "technique_id": item["technique_id"],
                "technique_name": item["technique_name"],
            }
        )

        ids.append(f"mitre-{item['technique_id']}-{i}")

    collection.add(
        documents=documents,
        metadatas=metadatas,
        ids=ids,
    )

    return len(documents)


def main():
    cis_path = CORPUS_DIR / "cis" / "cis-azure-foundations.pdf"
    kvkk_path = CORPUS_DIR / "kvkk" / "kvkk-6698.pdf"
    mitre_path = CORPUS_DIR / "mitre" / "enterprise-attack.json"

    print("Kaynaklar okunuyor...")

    cis_text = read_pdf(cis_path)
    kvkk_text = read_pdf(kvkk_path)
    mitre_techniques = read_mitre_json(mitre_path)

    print("Kaynaklar okundu.")
    print("Embedding modeli hazirlaniyor...")

    embedding_function = SentenceTransformerEmbeddingFunction(
        model_name="BAAI/bge-m3"
    )

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    try:
        client.delete_collection("sentinelmind_rag")
        print("Eski index silindi.")
    except Exception:
        pass

    collection = client.create_collection(
        name="sentinelmind_rag",
        embedding_function=embedding_function,
        metadata={
            "description": "SentinelMind AI RAG corpus"
        },
    )

    print("CIS ChromaDB'ye yaziliyor...")
    cis_count = add_text_source(
        collection,
        "cis_azure",
        cis_text,
    )

    print("KVKK ChromaDB'ye yaziliyor...")
    kvkk_count = add_text_source(
        collection,
        "kvkk",
        kvkk_text,
    )

    print("MITRE ChromaDB'ye yaziliyor...")
    mitre_count = add_mitre_source(
        collection,
        mitre_techniques,
    )

    print()
    print("INDEX OLUSTURULDU")
    print("----------------------------")
    print(f"CIS kaydi:   {cis_count}")
    print(f"KVKK kaydi:  {kvkk_count}")
    print(f"MITRE kaydi: {mitre_count}")
    print(f"Toplam:      {collection.count()}")
    print()
    print(f"ChromaDB konumu: {CHROMA_DIR}")


if __name__ == "__main__":
    main()