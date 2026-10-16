from typing import Iterable, List


class EmbeddingModel:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "RAG dependencies are missing. Install with: "
                "pip install sentence-transformers faiss-cpu"
            ) from exc
        self.model = SentenceTransformer(model_name)

    def encode(self, texts: Iterable[str]) -> List[List[float]]:
        encoded = self.model.encode(
            list(texts),
            normalize_embeddings=True,
            convert_to_numpy=True,
        )
        return encoded.tolist()
