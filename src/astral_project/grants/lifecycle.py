"""Grant creation, renewal, validation, and revocation policy."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import Grant, GrantVerificationContext, SignedGrant
from astral_project.state.sqlite import StateDatabase


class GrantValidator(Protocol):
    """Remote validator contract; it must return canonical, validated grant."""

    def __call__(self, grant: Grant) -> Grant: ...


class GrantApprover(Protocol):
    """Human approval contract over canonical grant changes."""

    def __call__(self, changes: tuple[str, ...]) -> bool: ...


@dataclass(frozen=True, slots=True)
class RenewalDecision:
    """Renewal comparison; widening requires explicit approval."""

    changes: tuple[str, ...]
    widened: bool


def _error(message: str, code: ErrorCode = ErrorCode.GRANT_INVALID) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="grant lifecycle operation was rejected",
        unsafe_reason="capability changes require fresh validation and explicit approval",
        next_action="review canonical grant and retry",
    )


def compare_grants(old: Grant, new: Grant) -> RenewalDecision:
    """Compare signed capability fields without treating expiry as widening."""
    changes: list[str] = []
    if old.host_id != new.host_id:
        changes.append("host_id")
    if old.ssh_host_key_fingerprint != new.ssh_host_key_fingerprint:
        changes.append("ssh_host_key_fingerprint")
    if old.remote_user != new.remote_user:
        changes.append("remote_user")
    if old.exports != new.exports:
        changes.append("exports")
    if old.requested_features != new.requested_features:
        changes.append("requested_features")
    if old.server_policy_hash != new.server_policy_hash:
        changes.append("server_policy_hash")
    if old.mandatory_extensions != new.mandatory_extensions:
        changes.append("mandatory_extensions")
    if old.optional_extensions != new.optional_extensions:
        changes.append("optional_extensions")
    widened = bool(
        old.host_id != new.host_id
        or old.ssh_host_key_fingerprint != new.ssh_host_key_fingerprint
        or old.remote_user != new.remote_user
        or set(new.exports) != set(old.exports)
        or not set(old.requested_features).issuperset(new.requested_features)
        or old.server_policy_hash != new.server_policy_hash
        or old.mandatory_extensions != new.mandatory_extensions
        or old.optional_extensions != new.optional_extensions
    )
    return RenewalDecision(tuple(changes), widened)


class GrantLifecycle:
    """Orchestrate grant policy; storage remains transaction-owned by StateDatabase."""

    def __init__(self, database: StateDatabase) -> None:
        self.database = database

    def create(
        self,
        grant: Grant,
        *,
        validator: GrantValidator,
        approver: GrantApprover,
        signing_key: Ed25519PrivateKey,
        host_metadata: Mapping[str, object] | None = None,
    ) -> SignedGrant:
        """Validate remotely, obtain approval, then sign and store—never earlier."""
        try:
            canonical = validator(grant)
        except AstralError:
            raise
        except Exception as error:
            raise _error(
                f"remote grant validation failed: {error}", ErrorCode.DAEMON_UNAVAILABLE
            ) from error
        if not isinstance(canonical, Grant):
            raise _error("remote validator returned invalid canonical grant")
        changes = _canonical_changes(grant, canonical)
        if changes and not approver(changes):
            raise _error("human approval rejected canonical grant changes")
        if not changes and not approver(()):
            raise _error("human approval was not recorded")
        signed = SignedGrant.create(canonical, signing_key)
        self.database.store_signed_grant(
            signed,
            host_key_fingerprint=canonical.ssh_host_key_fingerprint,
            remote_user=canonical.remote_user,
            host_metadata={} if host_metadata is None else host_metadata,
            issuer_key=signing_key.public_key(),
        )
        return signed

    def renew(
        self,
        current: SignedGrant,
        proposed: Grant,
        *,
        validator: GrantValidator,
        approver: GrantApprover,
        signing_key: Ed25519PrivateKey,
        host_metadata: Mapping[str, object],
    ) -> SignedGrant:
        """Renew after fresh validation; changed capability fields need approval."""
        if current.grant.grant_id == proposed.grant_id:
            raise _error("renewal requires a fresh grant identifier")
        canonical = validator(proposed)
        if not isinstance(canonical, Grant):
            raise _error("remote validator returned invalid renewed grant")
        decision = compare_grants(current.grant, canonical)
        if decision.widened and not approver(decision.changes):
            raise _error("renewal would widen capability without approval")
        if canonical != proposed:
            canonical_changes = _canonical_changes(proposed, canonical)
            if canonical_changes and not approver(canonical_changes):
                raise _error("human approval rejected renewed canonical changes")
        signed = SignedGrant.create(canonical, signing_key)
        self.database.store_signed_grant(
            signed,
            host_key_fingerprint=canonical.ssh_host_key_fingerprint,
            remote_user=canonical.remote_user,
            host_metadata=host_metadata,
            issuer_key=signing_key.public_key(),
        )
        return signed

    def validate(
        self,
        signed: SignedGrant,
        *,
        issuer_key: Ed25519PublicKey,
        context: GrantVerificationContext,
    ) -> Grant:
        return self.database.validate_signed_grant(signed, issuer_key=issuer_key, context=context)

    def revoke(
        self,
        grant_id: str,
        *,
        reason: str,
        remote_revoke: Callable[[SignedGrant], None] | None = None,
    ) -> str:
        return self.database.revoke_grant(grant_id, reason=reason, remote_revoke=remote_revoke)


def _canonical_changes(requested: Grant, canonical: Grant) -> tuple[str, ...]:
    changes: list[str] = []
    for field in (
        "host_id",
        "ssh_host_key_fingerprint",
        "remote_user",
        "issued_at",
        "not_before",
        "expires_at",
        "exports",
        "requested_features",
        "server_policy_hash",
        "mandatory_extensions",
        "optional_extensions",
    ):
        if getattr(requested, field) != getattr(canonical, field):
            changes.append(field)
    return tuple(changes)
