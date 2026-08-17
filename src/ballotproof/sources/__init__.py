"""Source-specific adapter contracts."""

from ballotproof.sources.inec_irev import (
    IREV_BASE_URL,
    IREV_SOURCE_ID,
    adapter_manifest,
    default_policy,
)

__all__ = [
    "IREV_BASE_URL",
    "IREV_SOURCE_ID",
    "adapter_manifest",
    "default_policy",
]
