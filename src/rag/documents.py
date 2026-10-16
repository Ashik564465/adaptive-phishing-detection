from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass
class RAGDocument:
    id: str
    title: str
    category: str
    content: str
    tags: List[str]

    def to_text(self) -> str:
        return (
            f"Title: {self.title}\n"
            f"Category: {self.category}\n"
            f"Tags: {', '.join(self.tags)}\n"
            f"Content: {self.content}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "RAGDocument":
        required = ("id", "title", "category", "content", "tags")
        missing = [field for field in required if field not in value]
        if missing:
            raise ValueError(f"RAG document missing fields: {missing}")
        if not isinstance(value["tags"], list):
            raise ValueError("RAG document tags must be a list")
        return cls(
            id=str(value["id"]),
            title=str(value["title"]),
            category=str(value["category"]),
            content=str(value["content"]),
            tags=[str(tag) for tag in value["tags"]],
        )
