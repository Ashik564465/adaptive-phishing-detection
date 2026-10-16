import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from src.rag.documents import RAGDocument


class VectorStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.index_path = self.directory / "index.faiss"
        self.documents_path = self.directory / "documents.json"
        self.index = None
        self.documents: List[RAGDocument] = []

    def build(self, embeddings: Sequence[Sequence[float]], documents: List[RAGDocument]):
        try:
            import faiss
            import numpy as np
        except ImportError as exc:
            raise RuntimeError(
                "RAG dependencies are missing. Install with: "
                "pip install sentence-transformers faiss-cpu"
            ) from exc

        if not embeddings:
            raise ValueError("Cannot build a vector store without documents")
        matrix = np.asarray(embeddings, dtype="float32")
        index = faiss.IndexFlatIP(matrix.shape[1])
        index.add(matrix)
        self.directory.mkdir(parents=True, exist_ok=True)
        faiss.write_index(index, str(self.index_path))
        self.documents_path.write_text(
            json.dumps([document.to_dict() for document in documents], indent=2),
            encoding="utf-8",
        )
        self.index = index
        self.documents = documents

    def load(self):
        try:
            import faiss
        except ImportError as exc:
            raise RuntimeError(
                "RAG dependencies are missing. Install with: "
                "pip install sentence-transformers faiss-cpu"
            ) from exc
        if not self.index_path.exists() or not self.documents_path.exists():
            raise FileNotFoundError(
                f"RAG index is missing: {self.index_path}. "
                "Run: python -m src.rag.ingest"
            )
        self.index = faiss.read_index(str(self.index_path))
        values = json.loads(self.documents_path.read_text(encoding="utf-8"))
        self.documents = [RAGDocument.from_dict(value) for value in values]
        if self.index.ntotal != len(self.documents):
            raise ValueError("RAG index and document metadata lengths differ")
        return self

    def search(self, embedding: Sequence[float], top_k: int = 5) -> List[Dict[str, Any]]:
        if self.index is None:
            raise RuntimeError("Vector store must be loaded before searching")
        import numpy as np

        scores, positions = self.index.search(
            np.asarray([embedding], dtype="float32"),
            min(top_k, len(self.documents)),
        )
        return [
            {
                "score": float(score),
                "document": self.documents[int(position)].to_dict(),
            }
            for score, position in zip(scores[0], positions[0])
            if position >= 0
        ]
