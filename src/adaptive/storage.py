from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class AdaptiveMemoryStorageError(RuntimeError):
    """Base error for adaptive-memory storage failures."""


class AdaptiveMemoryConcurrencyError(AdaptiveMemoryStorageError):
    """Raised when an adaptive-memory write loses an update race."""


@dataclass(frozen=True)
class StorageSnapshot:
    data: bytes
    version: str | None


class AdaptiveMemoryStorage(Protocol):
    def load(self) -> StorageSnapshot | None:
        ...

    def save(
        self,
        data: bytes,
        expected_version: str | None,
    ) -> str | None:
        ...


class LocalFileStorage:
    """Byte storage for the existing local adaptive-memory file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> StorageSnapshot | None:
        if not self.path.exists():
            return None

        try:
            return StorageSnapshot(
                data=self.path.read_bytes(),
                version=None,
            )
        except OSError as error:
            raise AdaptiveMemoryStorageError(
                f"Failed to read adaptive memory from {self.path}: {error}"
            ) from error

    def save(
        self,
        data: bytes,
        expected_version: str | None,
    ) -> str | None:
        del expected_version

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self.path.with_suffix(
                f"{self.path.suffix}.tmp"
            )
            temporary_path.write_bytes(data)
            temporary_path.replace(self.path)
        except OSError as error:
            raise AdaptiveMemoryStorageError(
                f"Failed to write adaptive memory to {self.path}: {error}"
            ) from error

        return None


class S3AdaptiveMemoryStorage:
    """
    S3 byte storage using conditional writes for lost-update protection.

    An existing object's ETag is used as the version token. New objects use
    If-None-Match='*'; existing objects use If-Match=<loaded ETag>.
    """

    def __init__(
        self,
        client: Any,
        bucket: str,
        key: str,
        allow_initialize: bool = False,
    ):
        if not bucket.strip():
            raise ValueError("S3 adaptive-memory bucket cannot be empty.")
        if not key.strip():
            raise ValueError("S3 adaptive-memory key cannot be empty.")

        self.client = client
        self.bucket = bucket
        self.key = key
        self.allow_initialize = allow_initialize

    def load(self) -> StorageSnapshot | None:
        try:
            response = self.client.get_object(
                Bucket=self.bucket,
                Key=self.key,
            )
        except Exception as error:
            if self._is_missing_object(error):
                if self.allow_initialize:
                    return None
                raise AdaptiveMemoryStorageError(
                    "S3 adaptive-memory object is missing. "
                    "Set ADAPTIVE_MEMORY_S3_ALLOW_INITIALIZE=true "
                    "only when creating an empty memory is intentional."
                ) from error

            raise AdaptiveMemoryStorageError(
                f"Failed to load adaptive memory from s3://"
                f"{self.bucket}/{self.key}: {error}"
            ) from error

        try:
            data = response["Body"].read()
            etag = str(response["ETag"])
        except (KeyError, TypeError, AttributeError) as error:
            raise AdaptiveMemoryStorageError(
                "S3 adaptive-memory response did not contain a readable "
                "Body and ETag."
            ) from error

        if not etag.strip('"'):
            raise AdaptiveMemoryStorageError(
                "S3 adaptive-memory response contained an empty ETag."
            )

        return StorageSnapshot(data=data, version=etag)

    def save(
        self,
        data: bytes,
        expected_version: str | None,
    ) -> str:
        arguments = {
            "Bucket": self.bucket,
            "Key": self.key,
            "Body": data,
            "ContentType": "application/octet-stream",
        }

        if expected_version is None:
            arguments["IfNoneMatch"] = "*"
        else:
            arguments["IfMatch"] = expected_version

        try:
            response = self.client.put_object(**arguments)
        except Exception as error:
            if self._is_conflict(error):
                raise AdaptiveMemoryConcurrencyError(
                    "Adaptive-memory object changed in S3 before it could "
                    "be updated. Reload memory and retry the feedback."
                ) from error

            raise AdaptiveMemoryStorageError(
                f"Failed to persist adaptive memory to s3://"
                f"{self.bucket}/{self.key}: {error}"
            ) from error

        etag = str(response.get("ETag", ""))
        if not etag.strip('"'):
            raise AdaptiveMemoryStorageError(
                "S3 adaptive-memory write did not return an ETag."
            )

        return etag

    @staticmethod
    def _error_code(error: Exception) -> str:
        response = getattr(error, "response", None)
        if isinstance(response, dict):
            error_data = response.get("Error", {})
            if isinstance(error_data, dict):
                return str(error_data.get("Code", ""))
        return ""

    @classmethod
    def _is_missing_object(cls, error: Exception) -> bool:
        return cls._error_code(error) in {"NoSuchKey", "404", "NotFound"}

    @classmethod
    def _is_conflict(cls, error: Exception) -> bool:
        if cls._error_code(error) in {
            "PreconditionFailed",
            "412",
            "ConditionalRequestConflict",
        }:
            return True

        response = getattr(error, "response", None)
        if isinstance(response, dict):
            metadata = response.get("ResponseMetadata", {})
            if isinstance(metadata, dict):
                return metadata.get("HTTPStatusCode") == 409

        return False
