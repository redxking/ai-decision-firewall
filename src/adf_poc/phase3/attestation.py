from __future__ import annotations

import hashlib
import hmac
from types import MappingProxyType
from typing import Any, Mapping

from adf_poc.utils import canonical_json


def evidence_attestation_payload(
    *,
    evidence_id: str,
    subject_target_id: str,
    source_type: str,
    source_instance: str,
    provenance_id: str,
    provenance_verified: bool,
    integrity_status: str,
    observed_at: str,
    content_sha256: str,
    supports: list[str] | tuple[str, ...],
    contradicts: list[str] | tuple[str, ...],
    relevance: float,
) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id,
        "subject_target_id": subject_target_id,
        "source_type": source_type,
        "source_instance": source_instance,
        "provenance_id": provenance_id,
        "provenance_verified": bool(provenance_verified),
        "integrity_status": str(integrity_status),
        "observed_at": observed_at,
        "content_sha256": content_sha256,
        "supports": sorted(str(value) for value in supports),
        "contradicts": sorted(str(value) for value in contradicts),
        "relevance": float(relevance),
    }


def sign_evidence_attestation(*, key: bytes, **fields: Any) -> str:
    if len(key) < 32:
        raise ValueError("Evidence attestation keys must be at least 32 bytes.")
    payload = evidence_attestation_payload(**fields)
    return hmac.new(
        key,
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def derive_synthetic_source_keys(
    master_key: bytes, source_instances: list[str] | tuple[str, ...] | set[str]
) -> dict[str, bytes]:
    """Derive process-local test keys; no key is stored in repository config."""

    if len(master_key) < 32:
        raise ValueError("Synthetic source master key must be at least 32 bytes.")
    return {
        source: hmac.new(master_key, source.encode("utf-8"), hashlib.sha256).digest()
        for source in sorted(source_instances)
    }


class EvidenceAttestationVerifier:
    __slots__ = ("__keys",)

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        required_source_instances: set[str] | None = None,
    ) -> None:
        if any(type(name) is not str or not name for name in keys):
            raise TypeError("Evidence attestation key names must be non-empty strings.")
        if any(type(value) is not bytes for value in keys.values()):
            raise TypeError("Evidence attestation keys must be exact bytes values.")
        frozen_keys = {name: value[:] for name, value in keys.items()}
        if any(len(value) < 32 for value in frozen_keys.values()):
            raise ValueError(
                "Every evidence attestation key must be at least 32 bytes."
            )
        key_digests = [hashlib.sha256(value).digest() for value in frozen_keys.values()]
        if len(key_digests) != len(set(key_digests)):
            raise ValueError(
                "Each trusted source instance requires distinct attestation key material."
            )
        required = required_source_instances or set()
        missing = set(required) - set(frozen_keys)
        extra = set(frozen_keys) - set(required) if required else set()
        if missing:
            raise ValueError(
                "Evidence attestation keys are missing trusted sources: "
                + ", ".join(sorted(missing))
            )
        if required and extra:
            raise ValueError(
                "Evidence attestation keys include unregistered sources: "
                + ", ".join(sorted(extra))
            )
        self.__keys = MappingProxyType(frozen_keys)

    def verify(self, item: Any) -> bool:
        key = self.__keys.get(str(item.source_instance))
        if key is None:
            return False
        expected = sign_evidence_attestation(
            key=key,
            evidence_id=str(item.id),
            subject_target_id=str(item.subject_target_id),
            source_type=str(item.source_type),
            source_instance=str(item.source_instance),
            provenance_id=str(item.provenance.id),
            provenance_verified=bool(item.provenance.verified),
            integrity_status=str(item.integrity.status.value),
            observed_at=str(item.observed_at),
            content_sha256=str(item.integrity.content_sha256),
            supports=list(item.supports),
            contradicts=list(item.contradicts),
            relevance=float(item.relevance),
        )
        return hmac.compare_digest(expected, str(item.provenance.signature))
