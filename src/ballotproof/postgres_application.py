from ballotproof.postgres_application_db import PostgresApplicationDatabaseMixin
from ballotproof.postgres_application_shared import (
    PostgresApplicationView,
    PostgresCutover,
    PostgresEquivalenceReport,
    application_records_sha256,
)
from ballotproof.postgres_artifacts import PostgresArtifactMixin
from ballotproof.postgres_cutover import PostgresCutoverMixin
from ballotproof.postgres_evidence_extractions import PostgresEvidenceExtractionMixin
from ballotproof.postgres_evidence_store import PostgresEvidenceStore
from ballotproof.postgres_evidence_versions import PostgresEvidenceVersionMixin
from ballotproof.postgres_registry_store import PostgresRegistryMixin, PostgresRegistryStore


class PostgresApplicationStore(
    PostgresRegistryMixin,
    PostgresEvidenceExtractionMixin,
    PostgresEvidenceVersionMixin,
    PostgresArtifactMixin,
    PostgresCutoverMixin,
    PostgresApplicationDatabaseMixin,
):
    pass


__all__ = [
    "PostgresApplicationStore",
    "PostgresApplicationView",
    "PostgresCutover",
    "PostgresEquivalenceReport",
    "PostgresEvidenceStore",
    "PostgresRegistryStore",
    "application_records_sha256",
]
