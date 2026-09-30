"""sro.json configuration.

Credentials are never stored in sro.json. The config only records *where* a
secret lives (an environment variable name or a local secret-store path) so
that reading a project config can never disclose a token.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .util import read_json

DEFAULT_CONFIG_NAME = "sro.json"

#: Provider modes, weakest first. `off` means the provider is not registered.
PROVIDER_MODES = ("off", "public", "import_only", "readonly")

#: Credential sources. `none` is the default and requires no setup at all.
CREDENTIAL_SOURCES = ("none", "environment", "file")


@dataclass(slots=True)
class ProviderConfig:
    provider: str
    mode: str = "off"
    credentials: str = "none"
    base_url: str = ""
    token_env: str = ""
    token_file: str = ""
    submissions: bool = False
    browser_assisted: bool = False
    options: dict[str, Any] = field(default_factory=dict)
    root: Path | None = None

    def __post_init__(self) -> None:
        self.provider = self.provider.lower()
        if self.mode not in PROVIDER_MODES:
            raise ConfigError(
                f"provider {self.provider!r}: mode must be one of {PROVIDER_MODES}, got {self.mode!r}"
            )
        if self.credentials not in CREDENTIAL_SOURCES:
            raise ConfigError(
                f"provider {self.provider!r}: credentials must be one of {CREDENTIAL_SOURCES}"
            )
        if self.credentials == "environment" and not self.token_env:
            raise ConfigError(
                f"provider {self.provider!r}: credentials=environment requires token_env"
            )
        if self.credentials == "file" and not self.token_file:
            raise ConfigError(f"provider {self.provider!r}: credentials=file requires token_file")

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @property
    def wants_credentials(self) -> bool:
        return self.credentials != "none" and self.mode in {"readonly", "public"}

    def resolve_token(self) -> str:
        """Fetch the token from the configured source. Returns "" if absent.

        The value is never logged, never persisted to the manifest, and never
        included in an evidence record.
        """
        if self.credentials == "environment" and self.token_env:
            return os.environ.get(self.token_env, "").strip()
        if self.credentials == "file" and self.token_file:
            path = Path(self.token_file).expanduser()
            if not path.is_absolute() and self.root:
                path = self.root / path
            try:
                return path.read_text(encoding="utf-8").strip()
            except OSError:
                return ""
        return ""


@dataclass(slots=True)
class ModelRoute:
    name: str
    provider: str
    model: str
    external: bool = False
    description: str = ""

    @property
    def model_id(self) -> str:
        return f"{self.provider}/{self.model}"


@dataclass(slots=True)
class Config:
    root: Path
    version: int = 1
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    routes: dict[str, ModelRoute] = field(default_factory=dict)
    default_route: str = "auto"
    allow_external: bool = False
    rate_limit_per_minute: int = 60
    rate_limit_per_host_per_minute: int = 20
    require_confirmation: bool = True
    destructive_requires_ask: bool = True
    out_of_scope_action: str = "deny"
    unknown_scope_action: str = "deny"
    deny_private_networks: bool = True
    wildcard_includes_apex: bool = True
    data_dir: Path = field(default_factory=Path)
    raw: dict[str, Any] = field(default_factory=dict)

    # -- construction ------------------------------------------------------

    @classmethod
    def load(cls, root: str | Path | None = None, path: str | Path | None = None) -> "Config":
        base = Path(root or Path.cwd()).resolve()
        config_path = Path(path) if path else base / DEFAULT_CONFIG_NAME
        if not config_path.exists():
            config = cls(root=base, data_dir=base)
            config._apply_defaults()
            return config
        try:
            data = read_json(config_path)
        except (OSError, ValueError) as exc:
            raise ConfigError(f"could not read {config_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"{config_path} must contain a JSON object")
        return cls.from_dict(data, root=base)

    @classmethod
    def from_dict(cls, data: dict[str, Any], root: str | Path | None = None) -> "Config":
        base = Path(root or Path.cwd()).resolve()
        config = cls(root=base, raw=data)
        config.version = int(data.get("version", 1))

        data_dir = data.get("data_dir")
        config.data_dir = (base / data_dir).resolve() if data_dir else base

        providers = data.get("providers") or {}
        if not isinstance(providers, dict):
            raise ConfigError("providers must be an object")
        for name, entry in providers.items():
            if not isinstance(entry, dict):
                raise ConfigError(f"providers.{name} must be an object")
            known = {
                "mode",
                "credentials",
                "base_url",
                "token_env",
                "token_file",
                "submissions",
                "browser_assisted",
                "options",
            }
            unknown = set(entry) - known
            if unknown:
                raise ConfigError(
                    f"providers.{name}: unknown key(s) {sorted(unknown)}; "
                    "secrets and write settings are not configurable"
                )
            provider = ProviderConfig(
                provider=name,
                mode=str(entry.get("mode", "off")),
                credentials=str(entry.get("credentials", "none")),
                base_url=str(entry.get("base_url", "")),
                token_env=str(entry.get("token_env", "")),
                token_file=str(entry.get("token_file", "")),
                # Submissions are permanently off. The flag is accepted so an
                # existing config is not rejected, but it can never enable writes.
                submissions=False,
                browser_assisted=bool(entry.get("browser_assisted", False)),
                options=dict(entry.get("options") or {}),
            )
            provider.root = base
            config.providers[provider.provider] = provider

        models = data.get("models") or {}
        if not isinstance(models, dict):
            raise ConfigError("models must be an object")
        for name, entry in models.items():
            if not isinstance(entry, dict) or "provider" not in entry or "model" not in entry:
                raise ConfigError(f"models.{name} requires 'provider' and 'model'")
            provider_id = str(entry["provider"]).lower()
            # Locality is declared, not inferred. Guessing it from a provider
            # id is how a route named "local_reasoning" ends up pointing at a
            # hosted API and a sensitivity gate waves a payload through.
            if "external" in entry:
                external = bool(entry["external"])
            else:
                external = provider_id in _KNOWN_EXTERNAL_PROVIDERS or (
                    provider_id not in _LOCAL_PROVIDERS
                )
            config.routes[name] = ModelRoute(
                name=name,
                provider=provider_id,
                model=str(entry["model"]),
                external=external,
                description=str(entry.get("description", "")),
            )

        routing = data.get("routing") or {}
        if not isinstance(routing, dict):
            raise ConfigError("routing must be an object")
        config.default_route = str(routing.get("default", "auto"))
        config.allow_external = bool(routing.get("allow_external", False))

        policy = data.get("policy") or {}
        if not isinstance(policy, dict):
            raise ConfigError("policy must be an object")
        limits = policy.get("rate_limits") or {}
        if not isinstance(limits, dict):
            raise ConfigError("policy.rate_limits must be an object")
        config.rate_limit_per_minute = int(limits.get("global_per_minute", 60))
        config.rate_limit_per_host_per_minute = int(limits.get("per_host_per_minute", 20))
        config.require_confirmation = bool(policy.get("require_user_confirmation", True))
        config.destructive_requires_ask = bool(policy.get("destructive_requires_ask", True))
        config.out_of_scope_action = str(policy.get("out_of_scope", "deny")).lower()
        config.unknown_scope_action = str(policy.get("unknown_scope", "deny")).lower()
        # There is deliberately no "allow" option here. An unresolved target is
        # never permitted; the only question is whether the researcher is
        # prompted or the action is refused outright.
        if config.unknown_scope_action not in {"deny", "ask"}:
            raise ConfigError(
                "policy.unknown_scope must be \"deny\" or \"ask\"; "
                "an unresolved target can never be set to allow"
            )
        if config.out_of_scope_action != "deny":
            raise ConfigError("policy.out_of_scope must be \"deny\"; it cannot be relaxed")

        scope = data.get("scope") or {}
        if not isinstance(scope, dict):
            raise ConfigError("scope must be an object")
        config.deny_private_networks = bool(scope.get("deny_private_networks", True))
        config.wildcard_includes_apex = bool(scope.get("wildcard_includes_apex", True))

        config._apply_defaults()
        return config

    def _apply_defaults(self) -> None:
        if not self.routes:
            self.routes = {
                "fast_local": ModelRoute("fast_local", "ollama", "lfm2.5", external=False),
                "local_reasoning": ModelRoute("local_reasoning", "ollama", "qwen3:14b", external=False),
                "security_local": ModelRoute("security_local", "ollama", "spark-x2.5", external=False),
            }
        for name in ("bugcrowd", "hackerone", "intigriti"):
            self.providers.setdefault(name, ProviderConfig(provider=name, mode="off"))
            self.providers[name].root = self.root

    # -- accessors ---------------------------------------------------------

    def provider(self, name: str) -> ProviderConfig:
        key = (name or "").lower()
        if key not in self.providers:
            raise ConfigError(f"unknown provider: {name!r}")
        return self.providers[key]

    @property
    def engagements_dir(self) -> Path:
        return self.data_dir / "engagements"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        for path in (self.engagements_dir, self.evidence_dir, self.reports_dir, self.data_dir / "audit"):
            path.mkdir(parents=True, exist_ok=True)

    def public_summary(self) -> dict[str, Any]:
        """Config view safe to show the model or print. Never includes secrets."""
        return {
            "root": str(self.root),
            "providers": {
                name: {
                    "mode": p.mode,
                    "credentials_configured": p.credentials != "none",
                    "credential_source": p.credentials,
                    "submissions": False,
                }
                for name, p in sorted(self.providers.items())
            },
            "routes": {name: r.model_id for name, r in sorted(self.routes.items())},
            "default_route": self.default_route,
            "allow_external": self.allow_external,
            "rate_limits": {
                "global_per_minute": self.rate_limit_per_minute,
                "per_host_per_minute": self.rate_limit_per_host_per_minute,
            },
            "policy": {
                "require_user_confirmation": self.require_confirmation,
                "destructive_requires_ask": self.destructive_requires_ask,
                "out_of_scope": self.out_of_scope_action,
                "unknown_scope": self.unknown_scope_action,
            },
            "scope": {
                "deny_private_networks": self.deny_private_networks,
                "wildcard_includes_apex": self.wildcard_includes_apex,
            },
        }


#: Provider ids SRO recognises as on-premises inference.
_LOCAL_PROVIDERS = frozenset(
    {"ollama", "lmstudio", "llamacpp", "localai", "vllm", "localhost", "127.0.0.1", "sro-local"}
)

#: Provider ids SRO recognises as third-party. Anything in neither set is
#: treated as external, because failing closed on an unrecognised provider is
#: the safe direction for the sensitivity gate.
_KNOWN_EXTERNAL_PROVIDERS = frozenset(
    {
        "openai", "anthropic", "openrouter", "tokenrouter", "google", "gemini",
        "azure", "bedrock", "mistral", "cohere", "groq", "together", "fireworks",
        "deepseek", "moonshot", "xai", "perplexity", "codex", "github-copilot",
    }
)
