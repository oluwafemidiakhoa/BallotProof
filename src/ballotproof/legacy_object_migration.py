from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from ballotproof.raw_object_storage import (
    RawObjectKind,
    RawObjectRef,
    RawObjectStore,
    raw_object_store_from_env,
)

MigrationStatus = Literal["planned", "migrated", "corrupt", "skipped"]


@dataclass(frozen=True)
class LegacyObjectResult:
    kind: RawObjectKind
    legacy_path: str
    sha256: str
    size_bytes: int
    status: MigrationStatus
    target_path: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class LegacyMigrationReport:
    dry_run: bool
    results: tuple[LegacyObjectResult, ...]

    @property
    def ok(self) -> bool:
        return all(result.status in {"planned", "migrated", "skipped"} for result in self.results)

    @property
    def migrated(self) -> int:
        return sum(result.status == "migrated" for result in self.results)

    @property
    def planned(self) -> int:
        return sum(result.status == "planned" for result in self.results)

    @property
    def corrupt(self) -> int:
        return sum(result.status == "corrupt" for result in self.results)

    def to_json(self) -> str:
        return json.dumps(
            {
                "dry_run": self.dry_run,
                "ok": self.ok,
                "migrated": self.migrated,
                "planned": self.planned,
                "corrupt": self.corrupt,
                "results": [asdict(result) for result in self.results],
            },
            indent=2,
            sort_keys=True,
        )


_LEGACY_ROOTS: dict[RawObjectKind, str] = {
    "evidence": "objects",
    "source": "source_objects",
}


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _target_ref(kind: RawObjectKind, digest: str, size: int) -> RawObjectRef:
    return RawObjectRef(
        sha256=digest,
        size_bytes=size,
        object_path=f"raw/{kind}/{digest[:2]}/{digest[2:4]}/{digest}",
    )


def _legacy_files(root: Path, kind: RawObjectKind) -> Iterable[Path]:
    legacy_root = root / _LEGACY_ROOTS[kind]
    if not legacy_root.exists():
        return ()
    return sorted(path for path in legacy_root.rglob("*") if path.is_file())


def migrate_legacy_objects(
    root: str | Path,
    store: RawObjectStore,
    *,
    dry_run: bool = True,
    kinds: tuple[RawObjectKind, ...] = ("evidence", "source"),
) -> LegacyMigrationReport:
    """Verify and optionally copy legacy raw objects without deleting originals.

    Every legacy file is hashed independently. Its filename must equal the computed
    SHA-256 and it must be non-empty before it is eligible for migration. Apply mode
    writes through the v0.28 RawObjectStore and then reads the target back through
    that store, proving digest and byte-size equivalence.
    """

    base = Path(root)
    results: list[LegacyObjectResult] = []
    for kind in kinds:
        for legacy_path in _legacy_files(base, kind):
            digest, size = _sha256_file(legacy_path)
            expected_name = legacy_path.name.lower()
            ref = _target_ref(kind, digest, size)
            if size == 0:
                results.append(
                    LegacyObjectResult(
                        kind=kind,
                        legacy_path=str(legacy_path),
                        sha256=digest,
                        size_bytes=size,
                        status="corrupt",
                        error="legacy raw object is empty",
                    )
                )
                continue
            if expected_name != digest:
                results.append(
                    LegacyObjectResult(
                        kind=kind,
                        legacy_path=str(legacy_path),
                        sha256=digest,
                        size_bytes=size,
                        status="corrupt",
                        error="legacy filename does not match computed SHA-256",
                    )
                )
                continue

            if dry_run:
                results.append(
                    LegacyObjectResult(
                        kind=kind,
                        legacy_path=str(legacy_path),
                        sha256=digest,
                        size_bytes=size,
                        status="planned",
                        target_path=ref.object_path,
                    )
                )
                continue

            with legacy_path.open("rb") as source:
                stored = store.put_stream(kind, source, max_bytes=size)
            if stored.sha256 != digest or stored.size_bytes != size:
                results.append(
                    LegacyObjectResult(
                        kind=kind,
                        legacy_path=str(legacy_path),
                        sha256=digest,
                        size_bytes=size,
                        status="corrupt",
                        target_path=stored.object_path,
                        error="target reference does not match legacy digest and size",
                    )
                )
                continue
            target_bytes = store.read_bytes(stored)
            target_digest = hashlib.sha256(target_bytes).hexdigest()
            if len(target_bytes) != size or target_digest != digest:
                results.append(
                    LegacyObjectResult(
                        kind=kind,
                        legacy_path=str(legacy_path),
                        sha256=digest,
                        size_bytes=size,
                        status="corrupt",
                        target_path=stored.object_path,
                        error="target bytes are not equivalent to legacy object",
                    )
                )
                continue
            results.append(
                LegacyObjectResult(
                    kind=kind,
                    legacy_path=str(legacy_path),
                    sha256=digest,
                    size_bytes=size,
                    status="migrated",
                    target_path=stored.object_path,
                )
            )

    return LegacyMigrationReport(dry_run=dry_run, results=tuple(results))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify and migrate BallotProof legacy raw objects into v0.28 storage."
    )
    parser.add_argument("--root", required=True, help="BallotProof data directory")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write verified objects to the configured raw-object backend",
    )
    args = parser.parse_args()

    store = raw_object_store_from_env(args.root)
    report = migrate_legacy_objects(args.root, store, dry_run=not args.apply)
    print(report.to_json())
    return 0 if report.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
