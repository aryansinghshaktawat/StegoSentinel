"""
Quarantine storage abstraction for StegoSentinel.
Enforces safe path resolution, strict permissions (0600), and non-executable storage.
"""

import os
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from app.core.config import settings


class StorageBackend(ABC):
    @abstractmethod
    def store_file(self, content: bytes, filename: str) -> tuple[str, str]:
        """Store bytes and return (storage_reference, relative_or_absolute_path)."""

    @abstractmethod
    def read_file(self, storage_reference: str) -> bytes:
        """Read bytes by storage reference."""

    @abstractmethod
    def get_path(self, storage_reference: str) -> Path:
        """Get filesystem path for analysis."""


class LocalStorageBackend(StorageBackend):
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _safe_resolve(self, storage_reference: str) -> Path:
        # Prevent any path traversal using pure UUID / alphanumeric reference
        clean_ref = Path(storage_reference).name
        target = (self.base_dir / clean_ref).resolve()
        if not str(target).startswith(str(self.base_dir)):
            raise ValueError(f"Path traversal detected in storage reference: {storage_reference}")
        return target

    def store_file(self, content: bytes, filename: str) -> tuple[str, str]:
        # Generate random unique reference; never use original filename for storage path
        file_uuid = str(uuid.uuid4())
        target_path = self.base_dir / file_uuid

        # Write with strict restricted permissions (0600: read/write user only, NO execute)
        target_path.write_bytes(content)
        try:
            os.chmod(target_path, 0o600)
        except OSError:
            pass

        return file_uuid, str(target_path)

    def read_file(self, storage_reference: str) -> bytes:
        target = self._safe_resolve(storage_reference)
        if not target.exists():
            raise FileNotFoundError(f"Quarantined file not found: {storage_reference}")
        return target.read_bytes()

    def get_path(self, storage_reference: str) -> Path:
        target = self._safe_resolve(storage_reference)
        if not target.exists():
            raise FileNotFoundError(f"Quarantined file not found: {storage_reference}")
        return target


# Global storage instance
storage = LocalStorageBackend(settings.storage_path)
