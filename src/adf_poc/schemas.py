from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class IntegrityStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FAILED = "failed"


class Disposition(str, Enum):
    NO_ACTION = "NO_ACTION"
    INVESTIGATE = "INVESTIGATE"
    CONTAIN_REVERSIBLE = "CONTAIN_REVERSIBLE"
    ESCALATE_HUMAN = "ESCALATE_HUMAN"


@dataclass(slots=True)
class EvidenceEvent:
    event_id: str
    case_id: str
    source_type: str
    source_instance: str
    observed_at: str
    collected_at: str
    integrity: str
    provenance_id: str
    trust_score: float
    entity_refs: list[str]
    attributes: dict[str, Any] = field(default_factory=dict)
    untrusted_text: str = ""
    contains_instructional_content: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceEvent":
        return cls(**value)


@dataclass(slots=True)
class IdentityCase:
    case_id: str
    opened_at: str
    subject_id: str
    privilege_level: str
    break_glass: bool
    asset_id: str
    asset_criticality: float
    events: list[EvidenceEvent]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["events"] = [event.to_dict() for event in self.events]
        return data

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IdentityCase":
        data = dict(value)
        data["events"] = [EvidenceEvent.from_dict(row) for row in data.get("events", [])]
        return cls(**data)


@dataclass(slots=True)
class GroundTruth:
    case_id: str
    scenario: str
    compromised: bool
    expected_disposition: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
