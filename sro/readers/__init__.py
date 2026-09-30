"""Provider registry.

Adding a platform means adding a reader module and one entry here. Agents never
see a provider-specific schema: every reader normalizes into
`sro.core.engagement.Engagement`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..core.config import Config
from ..core.errors import ConfigError

#: host fragment -> provider. Ordered longest-first so a more specific fragment
#: wins over a generic one.
HOST_HINTS: tuple[tuple[str, str], ...] = (
    ("bugcrowd.com", "bugcrowd"),
    ("bugcrowd.dev", "bugcrowd"),
    ("hackerone.com", "hackerone"),
    ("intigriti.com", "intigriti"),
)

SUPPORTED_PROVIDERS = ("bugcrowd", "hackerone", "intigriti")


def detect_provider(source: str) -> str | None:
    """Infer the platform from a URL or program code.

    A bare code is ambiguous, so this only claims a provider when the input
    actually carries a host. Guessing wrong would send a read to the wrong
    platform, which is a worse failure than asking.
    """
    text = (source or "").strip().lower()
    if not text:
        return None
    if "://" in text:
        host = (urlsplit(text).hostname or "").lower()
    elif any(fragment in text for fragment, _ in HOST_HINTS):
        # Scheme-less authority, e.g. "bugcrowd.com/engagements/acme".
        host = text.split("/", 1)[0]
    else:
        return None
    for fragment, provider in HOST_HINTS:
        if host == fragment or host.endswith("." + fragment):
            return provider
    return None


def build_reader(config: Config, provider: str) -> Any:
    """Instantiate a reader. The reader is handed a config, not a transport."""
    name = (provider or "").strip().lower()
    if name not in SUPPORTED_PROVIDERS:
        raise ConfigError(
            f"unknown provider {provider!r}; supported: {', '.join(SUPPORTED_PROVIDERS)}"
        )
    provider_config = config.provider(name)

    if name == "bugcrowd":
        from .bugcrowd.reader import BugcrowdReader

        return BugcrowdReader(provider_config)
    if name == "hackerone":
        from .hackerone.reader import HackerOneReader

        return HackerOneReader(provider_config)
    from .intigriti.reader import IntigritiReader

    return IntigritiReader(provider_config)


def all_capabilities(config: Config) -> dict[str, Any]:
    """Advertise what each configured provider can read.

    This is what the model sees instead of a platform API: a list of typed read
    operations per provider, and an empty write list on every one of them.
    """
    out: dict[str, Any] = {}
    for name in SUPPORTED_PROVIDERS:
        try:
            provider_config = config.provider(name)
        except ConfigError:
            continue
        if provider_config.mode == "off":
            out[name] = {"enabled": False}
            continue
        reader = build_reader(config, name)
        capabilities = reader.capabilities().to_dict()
        capabilities["enabled"] = True
        capabilities["mode"] = provider_config.mode
        out[name] = capabilities
    return out
