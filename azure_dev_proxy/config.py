from __future__ import annotations

import ipaddress
import json
import os
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlsplit

import idna


@dataclass(frozen=True)
class Config:
    """
    Routing settings for Azure-authenticated HTTPS destinations.

    Attributes:
        token_rules: Host rules, with exact hosts and longer wildcard suffixes
            taking precedence regardless of configuration order.
        trusted_origins: Normalized additional HTTP(S) browser origins allowed
            to forward.
    """

    token_rules: tuple[TokenRule, ...]
    trusted_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "trusted_origins",
            tuple(self.normalize_origin(origin) for origin in self.trusted_origins),
        )

    @classmethod
    def parse(cls, value: object) -> Config:
        """Validate a decoded JSON configuration and normalize its hostnames."""
        required = {"token_rules"}
        if not isinstance(value, dict) or not required <= set(value) <= required | {
            "trusted_origins",
            "query_string_substitutions_by_host",
        }:
            raise ValueError(
                "Configuration requires token_rules; trusted_origins is optional"
            )
        rules = value["token_rules"]
        if not isinstance(rules, list):
            raise ValueError("Configuration requires a token-rule array")
        parsed = []
        for rule in rules:
            if (
                not isinstance(rule, dict)
                or not {"host"} <= set(rule) <= {"host", "resource"}
                or not isinstance(rule["host"], str)
                or rule.get("resource") is not None
                and not isinstance(rule["resource"], str)
            ):
                raise ValueError("Invalid token rule")
            parsed.append(TokenRule(rule["host"], rule.get("resource")))
        origins = value.get("trusted_origins", [])
        if not isinstance(origins, list) or not all(
            isinstance(origin, str) for origin in origins
        ):
            raise ValueError("Trusted origins must be an array of HTTP(S) origins")
        return cls(tuple(parsed), tuple(origins))

    @classmethod
    def defaults(cls) -> Config:
        """The bundled routing defaults, without reading or writing a user file."""
        return cls.parse(
            json.loads(cls._default_json(), object_pairs_hook=cls._unique_fields)
        )

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load JSON, atomically installing defaults if the file is missing."""
        try:
            data = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = cls._default_json()
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent
            ) as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
                try:
                    os.link(temporary.name, path)
                except FileExistsError:
                    pass
            data = path.read_text(encoding="utf-8")
        try:
            value = json.loads(data, object_pairs_hook=cls._unique_fields)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid JSON configuration at line {error.lineno}, column {error.colno}"
            ) from None
        return cls.parse(value)

    def as_dict(self) -> dict[str, object]:
        """Return the routing settings as a JSON-compatible object."""
        return {
            "token_rules": [asdict(rule) for rule in self.token_rules],
            "trusted_origins": list(self.trusted_origins),
        }

    @classmethod
    def update_rule(
        cls, path: Path, rule: TokenRule, *, delete: bool = False
    ) -> Config:
        """
        Atomically replace or delete a persisted hostname mapping.

        Args:
            path: Existing JSON configuration file. Writable symlinks are
                followed without replacing the symlink itself.
            rule: Mapping to save, or the hostname to remove when deleting.
            delete: Remove all mappings for this normalized hostname instead
                of saving the supplied mapping.

        Returns:
            The configuration after the successful write. File permissions
            and unrelated JSON settings are retained.

        Raises:
            OSError: The file cannot be read or replaced, or is read-only.
            ValueError: The current file is not a valid configuration.
        """
        path = path.resolve(strict=True)
        if not os.access(path, os.W_OK):
            raise PermissionError("The configuration file is not writable")
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=cls._unique_fields
        )
        current = cls.parse(value)
        value["token_rules"] = [
            entry
            for entry, parsed in zip(value["token_rules"], current.token_rules)
            if parsed.host != rule.host
        ]
        if not delete:
            value["token_rules"].append(asdict(rule))
        value.pop("query_string_substitutions_by_host", None)
        updated = cls.parse(value)
        temporary = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            delete=False,
        )
        temporary_path = Path(temporary.name)
        try:
            with temporary:
                temporary.write(json.dumps(value, indent=2, ensure_ascii=True) + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            temporary_path.chmod(stat.S_IMODE(path.stat().st_mode))
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)
        return updated

    def resource_for(self, origin: str) -> str | None:
        """
        Select this configuration's token audience for an HTTPS destination.

        Args:
            origin: Destination origin. Non-HTTPS origins always return None,
                even when a hostname rule matches.

        Returns:
            The most specific matching rule's resource, or the normalized
            destination origin when that rule has no explicit resource.
            Unmatched destinations return None.

        Raises:
            ValueError: An HTTPS origin has an invalid or missing authority.
        """
        parsed = urlsplit(origin)
        if parsed.scheme != "https":
            return None
        if not parsed.hostname:
            raise ValueError("An HTTPS destination origin is required")
        authority = self.normalize_authority(parsed.netloc)
        host = urlsplit("https://" + authority).hostname or ""
        rule = min(
            (rule for rule in self.token_rules if rule.matches(host)),
            key=lambda rule: rule.priority,
            default=None,
        )
        if rule is None:
            return None
        return rule.resource if rule.resource is not None else "https://" + authority

    @staticmethod
    def normalize_host(host: str) -> str:
        """
        Normalize a DNS hostname or IP address for routing and rule matching.

        Args:
            host: Hostname without a port or IPv6 brackets. DNS names use
                nontransitional UTS #46; trailing dots are removed.

        Raises:
            ValueError: The hostname is invalid.
        """
        host = host.rstrip(".")
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass
        try:
            host = (
                idna.encode(host, uts46=True, transitional=False, std3_rules=True)
                .decode("ascii")
                .rstrip(".")
            )
        except idna.IDNAError as error:
            raise ValueError("Invalid hostname") from error
        return host

    @classmethod
    def normalize_authority(cls, authority: str, *, default_port: int = 443) -> str:
        """
        Normalize a URL authority, rejecting credentials and invalid ports.

        Args:
            authority: Hostname or bracketed IPv6 address with an optional port.
            default_port: Port omitted from the result when explicitly present;
                defaults to HTTPS port 443. HTTP callers should pass 80.

        Raises:
            ValueError: The authority is invalid.
        """
        if (
            not authority
            or any(c in authority for c in "/\\?#@%")
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in authority)
        ):
            raise ValueError("Invalid destination authority")
        parsed = urlsplit("https://" + authority)
        if not parsed.hostname:
            raise ValueError("Missing destination hostname")
        # urlsplit().hostname lowercases Unicode before IDNA can apply UTS #46.
        raw_host = (
            parsed.netloc.partition("]")[0][1:]
            if parsed.netloc.startswith("[")
            else parsed.netloc.partition(":")[0]
        )
        host = cls.normalize_host(raw_host)
        port = parsed.port
        if authority.endswith(":") or port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid destination port")
        if ":" in host:
            host = f"[{host}]"
        return host if port in (None, default_port) else f"{host}:{port}"

    @classmethod
    def normalize_origin(cls, value: str) -> str:
        """
        Normalize an HTTP(S) browser origin, omitting its scheme's default port.

        Args:
            value: Exact HTTP(S) origin without credentials, path, query,
                fragment or wildcards.

        Raises:
            ValueError: The origin is invalid.
        """
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Trusted origins must not contain whitespace or controls")
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.path
            or "?" in value
            or "#" in value
        ):
            raise ValueError(
                "Trusted origins require an HTTP(S) scheme and no path, query or fragment"
            )
        default_port = 80 if parsed.scheme == "http" else 443
        authority = cls.normalize_authority(parsed.netloc, default_port=default_port)
        return f"{parsed.scheme}://{authority}"

    @staticmethod
    def default_path() -> Path:
        """The native per-user configuration path for the current platform."""
        if sys.platform == "win32":
            directory = os.environ.get("APPDATA")
            root = Path(directory) if directory else Path.home() / "AppData" / "Roaming"
        elif sys.platform == "darwin":
            root = Path.home() / "Library" / "Application Support"
        else:
            directory = os.environ.get("XDG_CONFIG_HOME")
            root = Path(directory) if directory else Path.home() / ".config"
        return root / "azure-dev-proxy" / "config.json"

    @staticmethod
    def _default_json() -> str:
        return (
            files("azure_dev_proxy")
            .joinpath("default-config.json")
            .read_text(encoding="utf-8")
        )

    @staticmethod
    def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON configuration field")
            result[key] = value
        return result


@dataclass(frozen=True)
class TokenRule:
    """
    A hostname pattern and the Azure token resource it selects.

    Attributes:
        host: Exact hostname or wildcard DNS suffix beginning with ``*.``.
        resource: HTTPS token audience, or None for the destination origin.
    """

    host: str
    resource: str | None = None

    def __post_init__(self) -> None:
        wildcard = self.host.startswith("*.")
        host = Config.normalize_host(self.host[2:] if wildcard else self.host)
        if wildcard and ":" in host:
            raise ValueError("Wildcard rules require a DNS suffix")
        object.__setattr__(self, "host", "*." + host if wildcard else host)
        if self.resource is not None:
            if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in self.resource):
                raise ValueError(
                    "Resource overrides must not contain whitespace or controls"
                )
            parsed = urlsplit(self.resource)
            if (
                parsed.scheme != "https"
                or not parsed.netloc
                or "?" in self.resource
                or "#" in self.resource
            ):
                raise ValueError(
                    "Resource overrides must be HTTPS URLs without query or fragment"
                )
            Config.normalize_authority(parsed.netloc)

    def matches(self, host: str) -> bool:
        host = Config.normalize_host(host)
        if self.host.startswith("*."):
            return host.endswith(self.host[1:]) and host != self.host[2:]
        return host == self.host

    @property
    def priority(self) -> tuple[bool, int, str]:
        """The exact-host-first, longest-suffix-first matching priority."""
        return self.host.startswith("*."), -len(self.host), self.host
