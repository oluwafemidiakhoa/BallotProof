from __future__ import annotations

import hashlib
import os
from typing import BinaryIO
from uuid import uuid4

from ballotproof.storage import StoredArtifact


class PostgresArtifactMixin:
    def put_artifact(self, stream: BinaryIO, *, max_bytes: int | None = None) -> StoredArtifact:
        temp_path = self.root / f".incoming-{uuid4().hex}"
        digest = hashlib.sha256()
        size = 0
        try:
            with temp_path.open("xb") as destination:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        raise ValueError(f"Evidence artifact exceeds {max_bytes} byte limit")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if size == 0:
                raise ValueError("Evidence artifact is empty")
            sha256 = digest.hexdigest()
            final_path = self.objects / sha256[:2] / sha256[2:4] / sha256
            final_path.parent.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                if final_path.stat().st_size != size:
                    raise ValueError("existing evidence object size does not match its digest path")
                existing_digest = hashlib.sha256()
                with final_path.open("rb") as existing:
                    while chunk := existing.read(1024 * 1024):
                        existing_digest.update(chunk)
                if existing_digest.hexdigest() != sha256:
                    raise ValueError(
                        "existing evidence object content does not match its digest path"
                    )
                temp_path.unlink()
            else:
                os.replace(temp_path, final_path)
                directory_fd = os.open(final_path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            return StoredArtifact(sha256=sha256, size_bytes=size, path=final_path)
        finally:
            temp_path.unlink(missing_ok=True)
