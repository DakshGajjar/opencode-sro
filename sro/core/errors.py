"""SRO error taxonomy.

Errors are deliberately typed so the policy layer can distinguish
"the user must decide" (ASK) from "this is forbidden" (DENY).
"""

from __future__ import annotations


class SROError(Exception):
    """Base class for every SRO failure."""

    def __init__(self, message: str = "", **details: object) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __str__(self) -> str:
        parts = [self.message]
        for key, value in self.details.items():
            parts.append(f"{key}={value}")
        return " | ".join(parts)


class ConfigError(SROError):
    """sro.json is missing or invalid."""


class ProviderError(SROError):
    """A platform reader could not complete a read."""


class ProviderAuthError(ProviderError):
    """Reader requires credentials that are not configured or were rejected."""


class ProviderUnavailableError(ProviderError):
    """Platform was unreachable or returned a non-success status."""


class ProviderSchemaError(ProviderError):
    """Platform returned a payload that does not match the expected shape."""


class ReadOnlyViolation(SROError):
    """A write-capable operation was attempted against a platform reader.

    This is a programming error, not a runtime condition. SRO does not ship
    write capability in the connector layer, so this should be unreachable.
    """


class NoEngagementError(SROError):
    """No engagement is loaded."""


class NotActivatedError(SROError):
    """An engagement is loaded but the researcher has not activated it."""


class ScopeDecisionRequired(SROError):
    """A target could not be resolved to IN_SCOPE or OUT_OF_SCOPE."""


class PolicyDenied(SROError):
    """The policy engine denied an action."""

    def __init__(self, reason: str, decision: dict | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decision = decision or {}


class PolicyAskRequired(SROError):
    """The policy engine requires explicit researcher approval."""

    def __init__(self, reason: str, decision: dict | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decision = decision or {}


class UnknownToolError(SROError):
    """A tool name was requested that the broker does not register."""


class UnknownCapabilityError(SROError):
    """A tool requested a capability it does not declare."""


class UntrustedContentError(SROError):
    """Content failed untrusted-data validation."""
