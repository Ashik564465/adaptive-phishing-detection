import json
from pathlib import Path

from src.rag.documents import RAGDocument
from src.rag.embeddings import EmbeddingModel
from src.rag.vector_store import VectorStore

BASE_DIR = Path(__file__).resolve().parents[2]
KNOWLEDGE_PATH = BASE_DIR / "data" / "rag" / "knowledge" / "phishing_knowledge.json"
STORE_PATH = BASE_DIR / "data" / "rag" / "vector_store"


def load_documents():
    values = json.loads(KNOWLEDGE_PATH.read_text(encoding="utf-8"))
    documents = [RAGDocument.from_dict(value) for value in values]
    if not documents:
        raise ValueError("Knowledge base is empty")
    return documents


def main():
    documents = load_documents()
    print(f"Loaded {len(documents)} RAG documents")
    print("Generating embeddings...")
    embeddings = EmbeddingModel().encode(document.to_text() for document in documents)
    print(f"Embedding dimension: {len(embeddings[0])}")
    print("Building FAISS index...")
    VectorStore(STORE_PATH).build(embeddings, documents)
    print("RAG index created successfully.")
    print(f"Documents: {len(documents)}")
    print(f"Vector dimension: {len(embeddings[0])}")
    print(f"Index: {STORE_PATH / 'index.faiss'}")
    print(f"Metadata: {STORE_PATH / 'documents.json'}")


if __name__ == "__main__":
    main()
