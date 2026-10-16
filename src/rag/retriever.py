from pathlib import Path
from typing import Any, Dict, List

from src.rag.embeddings import EmbeddingModel
from src.rag.vector_store import VectorStore


class RAGRetriever:
    def __init__(self, store_path: Path, model_name: str = "all-MiniLM-L6-v2"):
        self.embedding_model = EmbeddingModel(model_name)
        self.store = VectorStore(store_path).load()

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        embedding = self.embedding_model.encode([query])[0]
        return self.store.search(embedding, top_k)
