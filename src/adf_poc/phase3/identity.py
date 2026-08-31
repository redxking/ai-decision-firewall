from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from typing import Iterable

from adf_poc.utils import canonical_json

from .contracts import AgentSecurityStatus, AuthenticatedPrincipal


class PrincipalAuthenticationError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ResolvedPrincipal:
    resolution_id: str
    resolver_instance_id: str
    credential_sha256: str
    principal: AuthenticatedPrincipal
    signature: str

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "resolution_id": self.resolution_id,
            "resolver_instance_id": self.resolver_instance_id,
            "credential_sha256": self.credential_sha256,
            "principal": self.principal.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.unsigned_dict(), "signature": self.signature}


class TrustedPrincipalResolver:
    """Resolve opaque transport credentials to firewall-trusted principals.

    The request never supplies this credential or the resulting attributes.
    Records are injected at process construction by the trusted integration
    boundary. Only credential digests are retained by the resolver.
    """

    __slots__ = ("_records", "_sealed", "_signing_key", "_instance_id")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError(
                "Trusted principal resolver is immutable after construction."
            )
        object.__setattr__(self, name, value)

    def __init__(
        self,
        records: Iterable[tuple[bytes, AuthenticatedPrincipal]],
    ) -> None:
        frozen: list[tuple[bytes, AuthenticatedPrincipal]] = []
        seen_digests: set[bytes] = set()
        seen_principal_ids: set[str] = set()
        for credential, principal in records:
            if type(credential) is not bytes or len(credential) < 32:
                raise ValueError(
                    "Trusted invocation credentials must be at least 32 bytes."
                )
            if type(principal) is not AuthenticatedPrincipal:
                raise TypeError("Principal records must be typed trusted principals.")
            if (
                type(principal.authenticated) is not bool
                or not principal.authenticated
                or type(principal.human_session) is not bool
                or type(principal.id) is not str
                or not principal.id
                or type(principal.type) is not str
                or not principal.type
                or type(principal.identity_source) is not str
                or not principal.identity_source
                or type(principal.roles) is not tuple
                or type(principal.authority) is not tuple
                or any(type(row) is not str or not row for row in principal.roles)
                or any(type(row) is not str or not row for row in principal.authority)
                or type(principal.security_status) is not AgentSecurityStatus
            ):
                raise ValueError(
                    "Resolver records require a strictly typed authenticated principal."
                )
            digest = hashlib.sha256(credential).digest()
            if digest in seen_digests:
                raise ValueError("Trusted invocation credentials must be unique.")
            if principal.id in seen_principal_ids:
                raise ValueError(
                    "Trusted principal identifiers must resolve to exactly one record."
                )
            seen_digests.add(digest)
            seen_principal_ids.add(principal.id)
            frozen.append((digest, principal))
        if not frozen:
            raise ValueError("At least one trusted principal credential is required.")
        object.__setattr__(self, "_records", tuple(frozen))
        object.__setattr__(self, "_signing_key", secrets.token_bytes(32))
        object.__setattr__(self, "_instance_id", f"principal-resolver-{uuid.uuid4()}")
        object.__setattr__(self, "_sealed", True)

    def immutable_snapshot(self) -> "TrustedPrincipalResolver":
        snapshot = object.__new__(TrustedPrincipalResolver)
        object.__setattr__(snapshot, "_records", tuple(self._records))
        object.__setattr__(snapshot, "_signing_key", bytes(self._signing_key))
        object.__setattr__(snapshot, "_instance_id", self._instance_id)
        object.__setattr__(snapshot, "_sealed", True)
        return snapshot

    def credential_digests(self) -> tuple[bytes, ...]:
        """Return non-secret digests for cross-domain key-separation checks."""

        return tuple(digest for digest, _principal in self._records)

    def _sign(self, value: dict[str, object]) -> str:
        return hmac.new(
            self._signing_key,
            canonical_json(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def resolve(self, credential: bytes) -> ResolvedPrincipal:
        if type(credential) is not bytes or len(credential) < 32:
            raise PrincipalAuthenticationError(
                "INVOCATION_CREDENTIAL_INVALID",
                "Invocation credential is absent or malformed.",
            )
        observed = hashlib.sha256(credential).digest()
        matched: AuthenticatedPrincipal | None = None
        for expected, principal in self._records:
            if hmac.compare_digest(expected, observed):
                matched = principal
        if matched is None:
            raise PrincipalAuthenticationError(
                "INVOCATION_CREDENTIAL_REJECTED",
                "Invocation credential is not registered at the trusted boundary.",
            )
        unsigned: dict[str, object] = {
            "resolution_id": f"resolution-{uuid.uuid4()}",
            "resolver_instance_id": self._instance_id,
            "credential_sha256": hashlib.sha256(credential).hexdigest(),
            "principal": matched.to_dict(),
        }
        return ResolvedPrincipal(
            resolution_id=str(unsigned["resolution_id"]),
            resolver_instance_id=self._instance_id,
            credential_sha256=str(unsigned["credential_sha256"]),
            principal=matched,
            signature=self._sign(unsigned),
        )

    def verify_resolution(self, value: ResolvedPrincipal) -> AuthenticatedPrincipal:
        if type(value) is not ResolvedPrincipal:
            raise PrincipalAuthenticationError(
                "PRINCIPAL_RESOLUTION_INVALID",
                "Trusted principal resolution type is invalid.",
            )
        if value.resolver_instance_id != self._instance_id or not hmac.compare_digest(
            self._sign(value.unsigned_dict()), value.signature
        ):
            raise PrincipalAuthenticationError(
                "PRINCIPAL_RESOLUTION_INVALID",
                "Trusted principal resolution signature is invalid.",
            )
        return value.principal
