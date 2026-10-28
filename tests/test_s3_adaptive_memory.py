from __future__ import annotations

import hashlib
import io

import numpy as np
import pytest

from src.adaptive.feedback import create_feedback_record
from src.adaptive.knowledge_updater import (
    update_knowledge_from_feedback,
)
from src.adaptive.persistent_memory import PersistentAdaptiveMemory
from src.adaptive.storage import (
    AdaptiveMemoryConcurrencyError,
    AdaptiveMemoryStorageError,
    S3AdaptiveMemoryStorage,
)
from src.api import main
from src.embeddings.document_chunker import build_memory_document


class FakeEmbedder:
    def encode(self, text: str) -> np.ndarray:
        del text
        return np.array([1.0, 0.0, 0.0], dtype=np.float32)


class FakeS3Error(Exception):
    def __init__(self, code: str, status_code: int | None = None):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}
        if status_code is not None:
            self.response["ResponseMetadata"] = {
                "HTTPStatusCode": status_code,
            }


class FakeS3Client:
    def __init__(self, data: bytes | None = None):
        self.data = data
        self.write_count = 0
        self.put_calls: list[dict] = []
        self.fail_get: Exception | None = None
        self.fail_put: Exception | None = None

    def _etag(self) -> str:
        assert self.data is not None
        return hashlib.md5(self.data).hexdigest()

    def get_object(self, **kwargs):
        if self.fail_get is not None:
            raise self.fail_get
        if self.data is None:
            raise FakeS3Error("NoSuchKey")
        return {
            "Body": io.BytesIO(self.data),
            "ETag": f'"{self._etag()}"',
        }

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        if self.fail_put is not None:
            raise self.fail_put

        expected = kwargs.get("IfMatch")
        if (
            expected is not None
            and expected.strip('"') != self._etag()
        ):
            raise FakeS3Error("PreconditionFailed")
        if kwargs.get("IfNoneMatch") == "*" and self.data is not None:
            raise FakeS3Error("PreconditionFailed")

        self.data = kwargs["Body"]
        self.write_count += 1
        return {"ETag": f'"{self._etag()}"'}


def _document(message_id: str = "s3-001"):
    return build_memory_document(
        message_id=message_id,
        channel="EMAIL",
        label="phishing",
        text="Verify your account.",
        sender="attacker@example.com",
        receiver="user@example.com",
    )


def _memory(client: FakeS3Client, allow_initialize: bool = True):
    return PersistentAdaptiveMemory(
        embedder=FakeEmbedder(),
        storage=S3AdaptiveMemoryStorage(
            client=client,
            bucket="test-bucket",
            key="adaptive/memory.pkl",
            allow_initialize=allow_initialize,
        ),
    )


def test_loads_valid_adaptive_memory_and_preserves_metadata():
    client = FakeS3Client()
    memory = _memory(client)
    memory.add_document(_document())

    reloaded = _memory(client)
    result = reloaded.search(
        np.array([1.0, 0.0, 0.0], dtype=np.float32),
        top_k=1,
    )[0].document

    assert result == _document()
    assert reloaded.count() == 1
    np.testing.assert_allclose(
        reloaded.store._vectors[0],
        np.array([1.0, 0.0, 0.0], dtype=np.float32),
    )


def test_missing_object_requires_explicit_initialization():
    with pytest.raises(AdaptiveMemoryStorageError, match="missing"):
        _memory(FakeS3Client(), allow_initialize=False)

    assert _memory(FakeS3Client(), allow_initialize=True).count() == 0


def test_initial_creation_uses_if_none_match():
    client = FakeS3Client()
    memory = _memory(client)

    memory.add_document(_document())

    assert client.put_calls[0]["IfNoneMatch"] == "*"


def test_update_uses_current_etag_in_if_match():
    client = FakeS3Client()
    first = _memory(client)
    first.add_document(_document("first"))
    current_etag = f'"{client._etag()}"'
    second = _memory(client)

    second.add_document(_document("second"))

    assert client.put_calls[1]["IfMatch"] == current_etag


@pytest.mark.parametrize("code", ["404", "NotFound"])
def test_missing_object_error_codes_require_initialization(code):
    client = FakeS3Client()
    client.fail_get = FakeS3Error(code)

    with pytest.raises(AdaptiveMemoryStorageError, match="missing"):
        _memory(client, allow_initialize=False)


def test_get_object_permission_error_is_not_treated_as_missing():
    client = FakeS3Client()
    client.fail_get = FakeS3Error("AccessDenied")

    with pytest.raises(AdaptiveMemoryStorageError, match="Failed to load"):
        _memory(client, allow_initialize=True)


@pytest.mark.parametrize(
    ("feedback_type", "label"),
    [
        ("confirmed_phishing", "phishing"),
        ("confirmed_legitimate", "legitimate"),
    ],
)
def test_accepted_feedback_is_persisted(feedback_type, label):
    client = FakeS3Client()
    memory = _memory(client)
    feedback = create_feedback_record(
        message_id=f"{label}-001",
        feedback_type=feedback_type,
        source="test",
        corrected_label=label,
    )
    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="SMS",
        text="A validated message.",
        sender="sender@example.com",
        receiver="receiver@example.com",
    )

    assert update.accepted is True
    memory.add_document(update.document)

    reloaded = _memory(client)
    assert reloaded.count() == 1
    assert reloaded.documents[0].label == label
    assert reloaded.documents[0].sender == "sender@example.com"


def test_ineligible_feedback_does_not_write():
    client = FakeS3Client()
    memory = _memory(client)
    feedback = create_feedback_record(
        message_id="rejected-001",
        feedback_type="unknown",
        source="test",
    )
    update = update_knowledge_from_feedback(
        feedback=feedback,
        channel="EMAIL",
        text="Unconfirmed message.",
    )

    assert update.accepted is False
    assert update.document is None
    assert client.write_count == 0


def test_s3_permission_error_is_not_silent():
    client = FakeS3Client()
    client.fail_put = FakeS3Error("AccessDenied")
    memory = _memory(client)

    with pytest.raises(AdaptiveMemoryStorageError, match="persist"):
        memory.add_document(_document())

    assert memory.count() == 0
    assert client.write_count == 0


def test_s3_network_error_is_not_silent():
    client = FakeS3Client()
    client.fail_put = ConnectionError("network unavailable")
    memory = _memory(client)

    with pytest.raises(AdaptiveMemoryStorageError, match="persist"):
        memory.add_document(_document())

    assert memory.count() == 0
    assert client.write_count == 0


def test_concurrent_update_conflict_is_reported():
    client = FakeS3Client()
    first = _memory(client)
    first.add_document(_document("first"))
    second = _memory(client)

    first.add_document(_document("second"))

    with pytest.raises(AdaptiveMemoryConcurrencyError, match="changed"):
        second.add_document(_document("third"))

    assert second.count() == 1
    assert _memory(client).count() == 2


def test_conditional_request_conflict_is_reported():
    client = FakeS3Client()
    client.fail_put = FakeS3Error("ConditionalRequestConflict")
    memory = _memory(client)

    with pytest.raises(AdaptiveMemoryConcurrencyError, match="changed"):
        memory.add_document(_document())

    assert memory.count() == 0
    assert client.write_count == 0


def test_http_412_conflict_is_reported():
    client = FakeS3Client()
    client.fail_put = FakeS3Error("PreconditionFailed", status_code=412)
    memory = _memory(client)

    with pytest.raises(AdaptiveMemoryConcurrencyError, match="changed"):
        memory.add_document(_document())

    assert memory.count() == 0
    assert memory.documents == []
    assert memory.store._vectors == []
    assert client.write_count == 0


def test_http_409_conflict_is_reported():
    client = FakeS3Client()
    client.fail_put = FakeS3Error("Conflict", status_code=409)
    memory = _memory(client)

    with pytest.raises(AdaptiveMemoryConcurrencyError, match="changed"):
        memory.add_document(_document())

    assert memory.count() == 0
    assert memory.documents == []
    assert memory.store._vectors == []
    assert client.write_count == 0


def test_health_reports_updated_memory_count(monkeypatch):
    client = FakeS3Client()
    memory = _memory(client)
    memory.add_document(_document())
    monkeypatch.setattr(main, "_adaptive_memory", memory)

    assert main.health()["adaptive_memory_documents"] == 1
