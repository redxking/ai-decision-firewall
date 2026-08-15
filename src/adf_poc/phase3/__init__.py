"""Simulation-only Phase 3 decision-control interfaces."""

from .approval import ApprovalError, HumanApprovalGate
from .audit import validate_phase3_lifecycle
from .config import (
    ActionPolicy,
    EvidencePolicyRules,
    Phase3PolicyConfig,
    PolicyValidationError,
    TargetRecord,
    TrustedSourcePolicy,
)
from .contracts import (
    ActionParameters,
    ActionRequest,
    ActionType,
    AgentClaims,
    AgentRecommendation,
    AgentSecurityStatus,
    AuthenticatedPrincipal,
    DecisionRequest,
    EvidenceIntegrity,
    EvidenceIntegrityStatus,
    EvidenceItem,
    EvidenceProvenance,
    RequestValidationError,
    TargetClaims,
    TargetClassification,
    TargetCriticality,
    TargetType,
    TrustLevel,
    load_decision_request_json,
    validate_decision_request_dict,
)
from .engine import Phase3DecisionFirewall
from .metrics import Phase3Metrics
from .models import DecisionOutcome, Phase3Result, VerificationStatus
from .identity import (
    PrincipalAuthenticationError,
    TrustedPrincipalResolver,
)

__all__ = [
    "ActionParameters",
    "ActionPolicy",
    "ActionRequest",
    "ActionType",
    "AgentClaims",
    "AgentRecommendation",
    "AgentSecurityStatus",
    "ApprovalError",
    "AuthenticatedPrincipal",
    "DecisionOutcome",
    "DecisionRequest",
    "EvidenceIntegrity",
    "EvidenceIntegrityStatus",
    "EvidenceItem",
    "EvidencePolicyRules",
    "EvidenceProvenance",
    "HumanApprovalGate",
    "Phase3DecisionFirewall",
    "Phase3Metrics",
    "Phase3PolicyConfig",
    "Phase3Result",
    "PrincipalAuthenticationError",
    "PolicyValidationError",
    "RequestValidationError",
    "TargetClaims",
    "TargetClassification",
    "TargetCriticality",
    "TargetRecord",
    "TargetType",
    "TrustedSourcePolicy",
    "TrustedPrincipalResolver",
    "TrustLevel",
    "VerificationStatus",
    "load_decision_request_json",
    "validate_phase3_lifecycle",
    "validate_decision_request_dict",
]
