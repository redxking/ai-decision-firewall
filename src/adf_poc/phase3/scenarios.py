from __future__ import annotations

import copy
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from adf_poc.utils import canonical_json

from .attestation import derive_synthetic_source_keys, sign_evidence_attestation
from .contracts import AuthenticatedPrincipal, EvidenceItem


def trusted_soc_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal.from_dict(
        {
            "id": "SOC_AGENT_01",
            "type": "SOC_AUTOMATION",
            "authenticated": True,
            "roles": ["SOC_ANALYST"],
            "authority": ["endpoint_containment"],
            "security_status": "TRUSTED",
            "identity_source": "synthetic_mtls_fixture",
        }
    )


def anonymous_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal.from_dict(
        {
            "id": "ANONYMOUS",
            "type": "UNAUTHENTICATED",
            "authenticated": False,
            "roles": [],
            "authority": [],
            "security_status": "UNKNOWN",
            "identity_source": "no_authenticated_transport",
        }
    )


def compromised_principal() -> AuthenticatedPrincipal:
    value = trusted_soc_principal().to_dict()
    value["id"] = "SOC_AGENT_COMPROMISED_01"
    value["security_status"] = "COMPROMISED"
    return AuthenticatedPrincipal.from_dict(value)


def tier0_human_principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal.from_dict(
        {
            "id": "HUMAN_INCIDENT_COMMANDER_01",
            "type": "HUMAN_ANALYST",
            "authenticated": True,
            "roles": ["HUMAN_APPROVER", "INCIDENT_COMMANDER"],
            "authority": ["endpoint_containment", "tier_0_containment"],
            "security_status": "TRUSTED",
            "identity_source": "synthetic_human_mtls_fixture",
            "human_session": True,
        }
    )


_SOURCES = {
    "asset_inventory": ("CMDB_PRIMARY", 0.98, "HIGH"),
    "endpoint": ("EDR_PRIMARY", 0.96, "HIGH"),
    "identity": ("IDP_PRIMARY", 0.96, "HIGH"),
    "network": ("NETWORK_PRIMARY", 0.94, "HIGH"),
    "threat_intel": ("CTI_PRIMARY", 0.82, "MEDIUM"),
}


def synthetic_source_keys(master_key: bytes) -> dict[str, bytes]:
    return derive_synthetic_source_keys(
        master_key, set(row[0] for row in _SOURCES.values())
    )


def synthetic_invocation_credential(
    master_key: bytes, principal: AuthenticatedPrincipal
) -> bytes:
    """Derive a process-local test credential; never serialize this value."""

    if len(master_key) < 32:
        raise ValueError("Synthetic invocation master key must be at least 32 bytes.")
    return hmac.new(
        master_key,
        canonical_json(principal.to_dict()).encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _evidence(
    *,
    evidence_id: str,
    subject_target_id: str,
    source_type: str,
    observed_at: datetime,
    source_keys: Mapping[str, bytes],
    supports: list[str] | None = None,
    contradicts: list[str] | None = None,
    payload: dict[str, Any] | None = None,
    untrusted_text: str = "",
    provenance_verified: bool = True,
    integrity_status: str = "VERIFIED",
) -> dict[str, Any]:
    source_instance, reliability, trust_level = _SOURCES[source_type]
    supported_claims = supports if supports is not None else ["COMPROMISE"]
    contradicted_claims = contradicts or []
    body = payload or {
        "synthetic": True,
        "signal": f"{source_type}_compromise_indicator",
    }
    digest = EvidenceItem.calculate_content_sha256(body, untrusted_text)
    observed_at_text = _iso(observed_at)
    provenance_id = f"prov-{evidence_id}"
    signature = sign_evidence_attestation(
        key=source_keys[source_instance],
        evidence_id=evidence_id,
        subject_target_id=subject_target_id,
        source_type=source_type,
        source_instance=source_instance,
        provenance_id=provenance_id,
        provenance_verified=provenance_verified,
        integrity_status=integrity_status,
        observed_at=observed_at_text,
        content_sha256=digest,
        supports=supported_claims,
        contradicts=contradicted_claims,
        relevance=0.95,
    )
    return {
        "id": evidence_id,
        "subject_target_id": subject_target_id,
        "source_type": source_type,
        "source_instance": source_instance,
        "provenance": {
            "id": provenance_id,
            "verified": provenance_verified,
            "signature": signature,
        },
        "integrity": {"status": integrity_status, "content_sha256": digest},
        "observed_at": observed_at_text,
        "reliability": reliability,
        "trust_level": trust_level,
        "supports": supported_claims,
        "contradicts": contradicted_claims,
        "relevance": 0.95,
        "payload": body,
        "untrusted_text": untrusted_text,
    }


def workstation_request(
    now: datetime,
    *,
    source_keys: Mapping[str, bytes],
    request_id: str = "P3-DEMO-WORKSTATION-ALLOW",
    duration_seconds: int = 900,
    preserve_management: bool = True,
    confidence: float = 0.91,
    recommendation: str = "ISOLATE",
) -> dict[str, Any]:
    observed = now - timedelta(seconds=60)
    evidence = [
        _evidence(
            evidence_id=f"ws-{index}-{source_type}",
            subject_target_id="WORKSTATION_042",
            source_type=source_type,
            observed_at=observed - timedelta(seconds=index * 5),
            source_keys=source_keys,
        )
        for index, source_type in enumerate(_SOURCES)
    ]
    return {
        "schema_version": "0.3.0",
        "request_id": request_id,
        "timestamp": _iso(now),
        "agent": {
            "id": "SOC_AGENT_01",
            "type": "SOC_AUTOMATION",
            "authenticated": True,
            "roles": ["SOC_ANALYST"],
            "authority": ["endpoint_containment"],
            "security_status": "TRUSTED",
        },
        "action": {
            "type": "NETWORK_ISOLATE",
            "target": "WORKSTATION_042",
            "parameters": {
                "duration_seconds": duration_seconds,
                "preserve_management": preserve_management,
            },
        },
        "target": {
            "id": "WORKSTATION_042",
            "type": "WORKSTATION",
            "criticality": "LOW",
            "classification": "INTERNAL",
            "dependencies": [],
        },
        "evidence": evidence,
        "agent_recommendation": recommendation,
        "agent_confidence": confidence,
        "context": {
            "environment": "synthetic_soc_demo",
            "case_type": "suspected_endpoint_compromise",
            "live_action": False,
        },
    }


def domain_controller_request(
    now: datetime,
    *,
    source_keys: Mapping[str, bytes],
    request_id: str = "P3-DEMO-DOMAIN-CONTROLLER",
    confidence: float = 0.96,
    recommendation: str = "ISOLATE",
) -> dict[str, Any]:
    fresh = now - timedelta(seconds=90)
    evidence = [
        _evidence(
            evidence_id="dc-cmdb",
            subject_target_id="DOMAIN_CONTROLLER_01",
            source_type="asset_inventory",
            observed_at=fresh,
            source_keys=source_keys,
        ),
        _evidence(
            evidence_id="dc-edr",
            subject_target_id="DOMAIN_CONTROLLER_01",
            source_type="endpoint",
            observed_at=fresh,
            source_keys=source_keys,
        ),
        _evidence(
            evidence_id="dc-idp",
            subject_target_id="DOMAIN_CONTROLLER_01",
            source_type="identity",
            observed_at=fresh,
            source_keys=source_keys,
        ),
        _evidence(
            evidence_id="dc-network-conflict",
            subject_target_id="DOMAIN_CONTROLLER_01",
            source_type="network",
            observed_at=fresh,
            source_keys=source_keys,
            supports=[],
            contradicts=["COMPROMISE"],
            payload={"synthetic": True, "traffic": "consistent_with_backup"},
        ),
        _evidence(
            evidence_id="dc-cti-stale",
            subject_target_id="DOMAIN_CONTROLLER_01",
            source_type="threat_intel",
            observed_at=now - timedelta(hours=12),
            source_keys=source_keys,
        ),
    ]
    return {
        "schema_version": "0.3.0",
        "request_id": request_id,
        "timestamp": _iso(now),
        "agent": {
            key: value
            for key, value in trusted_soc_principal().to_dict().items()
            if key
            not in {"identity_source", "human_session", "authentication_reason_code"}
        },
        "action": {
            "type": "NETWORK_ISOLATE",
            "target": "DOMAIN_CONTROLLER_01",
            "parameters": {
                "duration_seconds": 900,
                "preserve_management": True,
            },
        },
        "target": {
            "id": "DOMAIN_CONTROLLER_01",
            "type": "DOMAIN_CONTROLLER",
            "criticality": "TIER_0",
            "classification": "RESTRICTED",
            "dependencies": [
                "AUTHENTICATION_SERVICE",
                "DIRECTORY_SERVICES",
                "KERBEROS",
            ],
        },
        "evidence": evidence,
        "agent_recommendation": recommendation,
        "agent_confidence": confidence,
        "context": {
            "environment": "synthetic_soc_demo",
            "potential_authentication_outage": True,
            "live_action": False,
        },
    }


def _strip_trusted_only_agent_fields(value: dict[str, Any]) -> dict[str, Any]:
    request = copy.deepcopy(value)
    request["agent"].pop("identity_source", None)
    request["agent"].pop("human_session", None)
    request["agent"].pop("authentication_reason_code", None)
    return request


def valid_domain_controller_request(now: datetime, **kwargs: Any) -> dict[str, Any]:
    return domain_controller_request(now, **kwargs)


def request_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
