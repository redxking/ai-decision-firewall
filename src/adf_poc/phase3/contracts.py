from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from adf_poc.utils import (
    StrictJSONError,
    canonical_json,
    sha256_json,
    strict_json_loads,
)


SCHEMA_VERSION = "0.3.0"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_CONTEXT_BYTES = 64 * 1024
MAX_EVIDENCE_PAYLOAD_BYTES = 64 * 1024
MAX_REQUEST_FUTURE_SKEW = timedelta(minutes=5)
DEFAULT_REQUEST_SCHEMA = (
    Path(__file__).resolve().parents[3]
    / "contracts"
    / "v0.3.0"
    / "decision-request.schema.json"
)


class RequestValidationError(ValueError):
    """Fail-closed request error with a stable machine-readable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        self.code = reason_code
        self.message = message
        super().__init__(f"{reason_code}: {message}")


class AgentSecurityStatus(str, Enum):
    TRUSTED = "TRUSTED"
    DEGRADED = "DEGRADED"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"


class ActionType(str, Enum):
    NETWORK_ISOLATE = "NETWORK_ISOLATE"


class TargetType(str, Enum):
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    WORKSTATION = "WORKSTATION"


class TargetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    TIER_0 = "TIER_0"


class TargetClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class EvidenceIntegrityStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    FAILED = "FAILED"


class TrustLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNTRUSTED = "UNTRUSTED"


class AgentRecommendation(str, Enum):
    ISOLATE = "ISOLATE"
    DO_NOT_ISOLATE = "DO_NOT_ISOLATE"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True, slots=True)
class AgentClaims:
    """Untrusted identity and authority claims carried by the request."""

    id: str
    type: str
    authenticated: bool
    roles: tuple[str, ...]
    authority: tuple[str, ...]
    security_status: AgentSecurityStatus

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AgentClaims":
        return cls(
            id=str(value["id"]),
            type=str(value["type"]),
            authenticated=bool(value["authenticated"]),
            roles=tuple(str(item) for item in value["roles"]),
            authority=tuple(str(item) for item in value["authority"]),
            security_status=AgentSecurityStatus(value["security_status"]),
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "type": self.type,
            "authenticated": self.authenticated,
            "roles": list(self.roles),
            "authority": list(self.authority),
            "security_status": self.security_status.value,
        }
        return value


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Trusted identity resolved independently of request-carried claims."""

    id: str
    type: str
    authenticated: bool
    roles: tuple[str, ...]
    authority: tuple[str, ...]
    security_status: AgentSecurityStatus
    identity_source: str
    human_session: bool = False
    authentication_reason_code: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuthenticatedPrincipal":
        if not isinstance(value, dict):
            raise TypeError("Trusted principal input must be an object.")
        required_strings = ("id", "type", "identity_source")
        if any(
            type(value.get(name)) is not str or not value[name]
            for name in required_strings
        ):
            raise ValueError("Trusted principal identifiers must be nonempty strings.")
        if type(value.get("authenticated")) is not bool:
            raise TypeError("Trusted principal authenticated must be a boolean.")
        if "human_session" in value and type(value["human_session"]) is not bool:
            raise TypeError("Trusted principal human_session must be a boolean.")
        for name in ("roles", "authority"):
            rows = value.get(name)
            if (
                type(rows) is not list
                or len(rows) > 32
                or any(type(row) is not str or not row for row in rows)
                or len(rows) != len(set(rows))
            ):
                raise TypeError(
                    f"Trusted principal {name} must be a bounded unique string list."
                )
        if type(value.get("security_status")) is not str:
            raise TypeError("Trusted principal security_status must be a string enum.")
        if type(value.get("authentication_reason_code", "")) is not str:
            raise TypeError("Trusted principal authentication reason must be a string.")
        return cls(
            id=value["id"],
            type=value["type"],
            authenticated=value["authenticated"],
            roles=tuple(value["roles"]),
            authority=tuple(value["authority"]),
            security_status=AgentSecurityStatus(value["security_status"]),
            identity_source=value["identity_source"],
            human_session=value.get("human_session", False),
            authentication_reason_code=value.get("authentication_reason_code", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "type": self.type,
            "authenticated": self.authenticated,
            "roles": list(self.roles),
            "authority": list(self.authority),
            "security_status": self.security_status.value,
            "identity_source": self.identity_source,
            "human_session": self.human_session,
        }
        if self.authentication_reason_code:
            value["authentication_reason_code"] = self.authentication_reason_code
        return value


@dataclass(frozen=True, slots=True)
class ActionParameters:
    duration_seconds: int
    preserve_management: bool

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ActionParameters":
        return cls(
            duration_seconds=int(value["duration_seconds"]),
            preserve_management=bool(value["preserve_management"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration_seconds": self.duration_seconds,
            "preserve_management": self.preserve_management,
        }


@dataclass(frozen=True, slots=True)
class ActionRequest:
    type: ActionType
    target: str
    parameters: ActionParameters

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ActionRequest":
        return cls(
            type=ActionType(value["type"]),
            target=str(value["target"]),
            parameters=ActionParameters.from_dict(value["parameters"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "target": self.target,
            "parameters": self.parameters.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class TargetClaims:
    id: str
    type: TargetType
    criticality: TargetCriticality
    classification: TargetClassification
    dependencies: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TargetClaims":
        return cls(
            id=str(value["id"]),
            type=TargetType(value["type"]),
            criticality=TargetCriticality(value["criticality"]),
            classification=TargetClassification(value["classification"]),
            dependencies=tuple(str(item) for item in value["dependencies"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "criticality": self.criticality.value,
            "classification": self.classification.value,
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    id: str
    verified: bool
    signature: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceProvenance":
        return cls(
            id=str(value["id"]),
            verified=bool(value["verified"]),
            signature=str(value["signature"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "verified": self.verified,
            "signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class EvidenceIntegrity:
    status: EvidenceIntegrityStatus
    content_sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceIntegrity":
        return cls(
            status=EvidenceIntegrityStatus(value["status"]),
            content_sha256=str(value["content_sha256"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    id: str
    subject_target_id: str
    source_type: str
    source_instance: str
    provenance: EvidenceProvenance
    integrity: EvidenceIntegrity
    observed_at: str
    reliability: float
    trust_level: TrustLevel
    supports: tuple[str, ...]
    contradicts: tuple[str, ...]
    relevance: float
    payload: dict[str, Any]
    untrusted_text: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceItem":
        return cls(
            id=str(value["id"]),
            subject_target_id=str(value["subject_target_id"]),
            source_type=str(value["source_type"]),
            source_instance=str(value["source_instance"]),
            provenance=EvidenceProvenance.from_dict(value["provenance"]),
            integrity=EvidenceIntegrity.from_dict(value["integrity"]),
            observed_at=str(value["observed_at"]),
            reliability=float(value["reliability"]),
            trust_level=TrustLevel(value["trust_level"]),
            supports=tuple(str(item) for item in value["supports"]),
            contradicts=tuple(str(item) for item in value["contradicts"]),
            relevance=float(value["relevance"]),
            payload=copy.deepcopy(value["payload"]),
            untrusted_text=str(value["untrusted_text"]),
        )

    @staticmethod
    def calculate_content_sha256(payload: dict[str, Any], untrusted_text: str) -> str:
        """Bind the exact structured payload and untrusted text as one object."""

        return sha256_json({"payload": payload, "untrusted_text": untrusted_text})

    def computed_content_sha256(self) -> str:
        return self.calculate_content_sha256(self.payload, self.untrusted_text)

    def content_digest_matches(self) -> bool:
        """Return integrity agreement; policy is applied by the evidence engine."""

        return self.computed_content_sha256() == self.integrity.content_sha256

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subject_target_id": self.subject_target_id,
            "source_type": self.source_type,
            "source_instance": self.source_instance,
            "provenance": self.provenance.to_dict(),
            "integrity": self.integrity.to_dict(),
            "observed_at": self.observed_at,
            "reliability": self.reliability,
            "trust_level": self.trust_level.value,
            "supports": list(self.supports),
            "contradicts": list(self.contradicts),
            "relevance": self.relevance,
            "payload": copy.deepcopy(self.payload),
            "untrusted_text": self.untrusted_text,
        }


@dataclass(frozen=True, slots=True)
class DecisionRequest:
    schema_version: str
    request_id: str
    timestamp: str
    agent: AgentClaims
    action: ActionRequest
    target: TargetClaims
    evidence: tuple[EvidenceItem, ...]
    agent_recommendation: AgentRecommendation
    agent_confidence: float
    context: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DecisionRequest":
        return cls(
            schema_version=str(value["schema_version"]),
            request_id=str(value["request_id"]),
            timestamp=str(value["timestamp"]),
            agent=AgentClaims.from_dict(value["agent"]),
            action=ActionRequest.from_dict(value["action"]),
            target=TargetClaims.from_dict(value["target"]),
            evidence=tuple(EvidenceItem.from_dict(item) for item in value["evidence"]),
            agent_recommendation=AgentRecommendation(value["agent_recommendation"]),
            agent_confidence=float(value["agent_confidence"]),
            context=copy.deepcopy(value["context"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "agent": self.agent.to_dict(),
            "action": self.action.to_dict(),
            "target": self.target.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "agent_recommendation": self.agent_recommendation.value,
            "agent_confidence": self.agent_confidence,
            "context": copy.deepcopy(self.context),
        }

    def request_sha256(self) -> str:
        return sha256_json(self.to_dict())


def _json_depth(value: Any) -> int:
    maximum = 0
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        child, depth = pending.pop()
        maximum = max(maximum, depth)
        if isinstance(child, dict):
            pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list):
            pending.extend((item, depth + 1) for item in child)
    return maximum


def _encoded_size(value: Any, *, reason_code: str, label: str) -> int:
    try:
        return len(canonical_json(value).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise RequestValidationError(
            reason_code, f"{label} must contain finite canonical JSON values."
        ) from exc


def _parse_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp lacks an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def _load_request_schema(path: str | Path | None) -> dict[str, Any]:
    target = Path(path) if path is not None else DEFAULT_REQUEST_SCHEMA
    try:
        raw = target.read_bytes()
        if len(raw) > MAX_REQUEST_BYTES:
            raise RequestValidationError(
                "REQUEST_SCHEMA_INVALID_CONFIGURATION",
                "Decision-request schema exceeds its size bound.",
            )
        value = strict_json_loads(raw)
        if not isinstance(value, dict):
            raise RequestValidationError(
                "REQUEST_SCHEMA_INVALID_CONFIGURATION",
                "Decision-request schema must be a JSON object.",
            )
        Draft202012Validator.check_schema(value)
        return value
    except RequestValidationError:
        raise
    except (OSError, StrictJSONError, ValueError, UnicodeError, SchemaError) as exc:
        raise RequestValidationError(
            "REQUEST_SCHEMA_INVALID_CONFIGURATION",
            "Decision-request schema could not be loaded or validated.",
        ) from exc


def _schema_error_message(error: Any) -> str:
    path = ".".join(str(item) for item in error.absolute_path)
    prefix = f"{path}: " if path else ""
    return (prefix + error.message)[:500]


def validate_decision_request_dict(
    value: dict[str, Any],
    schema_path: str | Path | None = None,
    *,
    now: datetime | None = None,
) -> DecisionRequest:
    """Validate a decoded request and return its immutable typed representation."""

    if not isinstance(value, dict):
        raise RequestValidationError(
            "REQUEST_NOT_OBJECT", "Decision request must be a JSON object."
        )
    request_size = _encoded_size(
        value, reason_code="REQUEST_JSON_INVALID", label="Decision request"
    )
    if request_size > MAX_REQUEST_BYTES:
        raise RequestValidationError(
            "REQUEST_TOO_LARGE", "Decision request exceeds the 1 MiB bound."
        )
    if _json_depth(value) > MAX_JSON_DEPTH:
        raise RequestValidationError(
            "REQUEST_TOO_DEEP",
            f"Decision request exceeds the {MAX_JSON_DEPTH}-level nesting bound.",
        )
    if "schema_version" in value and value["schema_version"] != SCHEMA_VERSION:
        raise RequestValidationError(
            "UNSUPPORTED_SCHEMA_VERSION",
            f"Only decision-request schema version {SCHEMA_VERSION} is supported.",
        )

    schema = _load_request_schema(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: (
            tuple(str(item) for item in error.absolute_path),
            error.message,
        ),
    )
    if errors:
        raise RequestValidationError(
            "REQUEST_SCHEMA_INVALID", _schema_error_message(errors[0])
        )

    if value["action"]["target"] != value["target"]["id"]:
        raise RequestValidationError(
            "TARGET_BINDING_MISMATCH",
            "action.target must exactly match target.id.",
        )

    evidence_ids = [str(item["id"]) for item in value["evidence"]]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise RequestValidationError(
            "DUPLICATE_EVIDENCE_ID",
            "Evidence identifiers must be unique within a request.",
        )

    if (
        _encoded_size(
            value["context"],
            reason_code="REQUEST_JSON_INVALID",
            label="Request context",
        )
        > MAX_CONTEXT_BYTES
    ):
        raise RequestValidationError(
            "REQUEST_CONTEXT_TOO_LARGE",
            "Request context exceeds the 64 KiB bound.",
        )
    for item in value["evidence"]:
        if (
            _encoded_size(
                item["payload"],
                reason_code="REQUEST_JSON_INVALID",
                label=f"Evidence payload {item['id']}",
            )
            > MAX_EVIDENCE_PAYLOAD_BYTES
        ):
            raise RequestValidationError(
                "EVIDENCE_PAYLOAD_TOO_LARGE",
                f"Evidence payload {item['id']} exceeds the 64 KiB bound.",
            )
        overlap = set(item["supports"]) & set(item["contradicts"])
        if overlap:
            raise RequestValidationError(
                "EVIDENCE_STANCE_CONFLICT",
                f"Evidence {item['id']} cannot support and contradict the same claim.",
            )

    try:
        request_time = _parse_datetime(value["timestamp"])
        validation_time = now or datetime.now(timezone.utc)
        if validation_time.tzinfo is None or validation_time.utcoffset() is None:
            raise RequestValidationError(
                "REQUEST_CLOCK_INVALID",
                "Request validation clock must include a UTC offset.",
            )
        validation_time = validation_time.astimezone(timezone.utc)
        if request_time > validation_time + MAX_REQUEST_FUTURE_SKEW:
            raise RequestValidationError(
                "REQUEST_TIMESTAMP_FUTURE",
                "Request timestamp exceeds the permitted future clock skew.",
            )
        for item in value["evidence"]:
            observed_at = _parse_datetime(item["observed_at"])
            if observed_at > request_time + MAX_REQUEST_FUTURE_SKEW:
                raise RequestValidationError(
                    "EVIDENCE_TIMESTAMP_FUTURE",
                    f"Evidence {item['id']} occurs after the permitted request-time skew.",
                )
    except RequestValidationError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise RequestValidationError(
            "REQUEST_TIMESTAMP_INVALID",
            "Request and evidence timestamps must be RFC 3339 date-times with offsets.",
        ) from exc

    return DecisionRequest.from_dict(value)


def load_decision_request_json(
    raw: str | bytes,
    schema_path: str | Path | None = None,
    *,
    now: datetime | None = None,
) -> DecisionRequest:
    """Strict-decode, schema-validate, and type a Phase 3 decision request."""

    if not isinstance(raw, (str, bytes)):
        raise RequestValidationError(
            "REQUEST_JSON_INVALID", "Decision request must be JSON text or bytes."
        )
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(raw_bytes) > MAX_REQUEST_BYTES:
        raise RequestValidationError(
            "REQUEST_TOO_LARGE", "Decision request exceeds the 1 MiB bound."
        )
    try:
        value = strict_json_loads(raw)
    except (StrictJSONError, json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise RequestValidationError(
            "REQUEST_JSON_INVALID",
            "Decision request is not strict JSON; duplicate members and non-finite numbers are prohibited.",
        ) from exc
    if not isinstance(value, dict):
        raise RequestValidationError(
            "REQUEST_NOT_OBJECT", "Decision request must be a JSON object."
        )
    return validate_decision_request_dict(value, schema_path=schema_path, now=now)
