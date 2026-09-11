from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction


BASE_DIR = Path(__file__).resolve().parent
CHROMA_DIR = BASE_DIR / "chroma_db"


def search(collection, query, source, n_results=3):
    print("\n" + "=" * 90)
    print(f"KAYNAK: {source.upper()}")
    print(f"SORGU: {query}")
    print("=" * 90)

    results = collection.query(
        query_texts=[query],
        n_results=n_results,
        where={"source": source},
    )

    documents = results["documents"][0]
    metadatas = results["metadatas"][0]
    distances = results["distances"][0]

    for i, (document, metadata, distance) in enumerate(
        zip(documents, metadatas, distances),
        start=1,
    ):
        print(f"\nSONUC {i}")
        print(f"Distance: {distance:.4f}")

        if metadata.get("technique_id"):
            print(
                f"MITRE: {metadata.get('technique_id')} "
                f"- {metadata.get('technique_name')}"
            )

        print(document[:1000])
        print()


def main():
    embedding_function = SentenceTransformerEmbeddingFunction(
        model_name="BAAI/bge-m3"
    )

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    collection = client.get_collection(
        name="sentinelmind_rag",
        embedding_function=embedding_function,
    )

    search(
        collection,
        query=(
            "Azure Storage Account allows anonymous public access "
            "to blob data exposed to the internet."
        ),
        source="cis_azure",
    )

    search(
        collection,
        query=(
            "An attacker discovers publicly accessible cloud storage "
            "and obtains data stored in that cloud storage."
        ),
        source="mitre",
    )

    search(
        collection,
        query=(
            "Kişisel verilerin yetkisiz kişilerin erişimine açık hale "
            "gelmesi, veri güvenliği ve veri sorumlusunun yükümlülükleri"
        ),
        source="kvkk",
    )


if __name__ == "__main__":
    main()