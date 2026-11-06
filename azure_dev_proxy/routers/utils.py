from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus, urljoin, urlsplit

from aiohttp import web
from yarl import URL

from ..config import Config

LOG = logging.getLogger("azure_dev_proxy.proxy")
GRAPHQL_PREFIX = "/:graphiql/"


@dataclass
class ProxyCall:
    """
    Sanitized destination and token status for one request's log entry.

    Attributes:
        url: Destination URL with sensitive fields redacted.
        token: Whether an Azure token was attached to the upstream request.
        source: Token acquisition or local-response category.
        logged: Whether the request's single log entry has already been emitted.
    """

    url: str
    token: bool = False
    source: str = "not-attempted"
    logged: bool = False

    def emit(self, method: str) -> None:
        if not self.logged:
            LOG.info(
                "Proxy call url=%s method=%s token=%s source=%s",
                self.url,
                method,
                "yes" if self.token else "no",
                self.source,
            )
            self.logged = True


CALL_KEY = web.RequestKey("proxy_call", ProxyCall)


def validate_destination(request: web.Request, target: URL, *, port: int) -> ProxyCall:
    """
    Record a parsed destination and reject loops into the local proxy.

    Args:
        request: Request with its log context installed by the middleware.
        target: Parsed HTTP(S) destination.
        port: Local proxy listener port used to detect self-loops.

    Returns:
        The request's log context, updated with the sanitized destination.

    Raises:
        web.HTTPBadRequest: The destination loops back into the proxy.
    """
    call = request[CALL_KEY]
    call.url = log_url(str(target))
    host = target.host or ""
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if loopback and target.port == port:
        raise web.HTTPBadRequest(text="Destination loops back into this proxy\n")
    return call


def log_url(value: str) -> str:
    base, separator, raw_query = value.partition("?")
    query = []
    for parameter in raw_query.split("&"):
        key, equals, content = parameter.partition("=")
        normalized = re.sub(r"[^a-z0-9]", "", unquote_plus(key).lower())
        sensitive = any(
            word in normalized for word in ("token", "secret", "password", "signature")
        )
        sensitive = sensitive or normalized in {
            "key",
            "apikey",
            "sig",
            "code",
            "authorization",
            "credential",
        }
        query.append(key + equals + ("REDACTED" if sensitive and equals else content))
    value = base + separator + "&".join(query)
    value = re.sub(r"(?<=/)[^/?]*@", "REDACTED@", value)
    return "".join(
        character
        if ord(character) >= 32 and ord(character) != 127
        else f"\\x{ord(character):02x}"
        for character in value
    )


def parse_target(raw_path: str) -> URL:
    """
    Parse a proxy destination without re-encoding its path or query.

    Args:
        raw_path: Root-relative proxy path containing a bare hostname or an
            explicit HTTP(S) URL. Bare destinations default to HTTPS.

    Raises:
        ValueError: The route contains an invalid authority, fragment or path.
    """
    route, separator, query = raw_path.partition("?")
    if not route.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in raw_path):
        raise ValueError("Invalid proxy route")
    route = route[1:]
    scheme = "https"
    if route[:8].lower() == "https://":
        route = route[8:]
    elif route[:7].lower() == "http://":
        scheme = "http"
        route = route[7:]
    authority, _, path = route.partition("/")
    authority = Config.normalize_authority(
        authority, default_port=80 if scheme == "http" else 443
    )
    if "#" in raw_path or "\\" in path:
        raise ValueError("Invalid upstream path")
    return URL(
        scheme
        + "://"
        + authority
        + "/"
        + path
        + (separator + query if separator else ""),
        encoded=True,
    )


def rewrite_url(
    value: str,
    upstream: URL,
    local_origin: str,
    *,
    explicit_scheme: bool = False,
) -> str:
    """
    Resolve upstream navigation through the proxy, retaining encoded URL fields.

    Args:
        value: Absolute or relative navigation URL from the upstream.
        upstream: Destination URL against which relative references resolve.
        local_origin: Proxy origin used for the rewritten navigation.
        explicit_scheme: Include HTTPS explicitly rather than using a bare-host
            proxy path. HTTP targets always include their scheme.

    Raises:
        ValueError: The navigation target is invalid or does not use HTTP(S).
    """
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Invalid navigation URL")
    target = urlsplit(urljoin(str(upstream), value))
    if target.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) navigation targets are supported")
    authority = Config.normalize_authority(
        target.netloc, default_port=80 if target.scheme == "http" else 443
    )
    scheme = target.scheme + "://" if explicit_scheme or target.scheme == "http" else ""
    return (
        local_origin
        + "/"
        + scheme
        + authority
        + (target.path or "/")
        + ("?" + target.query if target.query else "")
        + ("#" + target.fragment if target.fragment else "")
    )


def rewrite_refresh(
    value: str,
    upstream: URL,
    local_origin: str,
    *,
    explicit_scheme: bool = False,
) -> str:
    """
    Rewrite a Refresh header's optional navigation target through the proxy.

    Args:
        value: Upstream Refresh header with a delay and optional URL.
        upstream: Destination URL against which relative references resolve.
        local_origin: Proxy origin used for the rewritten navigation.
        explicit_scheme: Include HTTPS explicitly, as in rewrite_url.

    Raises:
        ValueError: The header or its navigation target is invalid.
    """
    match = re.fullmatch(
        r"\s*(\d+(?:\.\d+)?)\s*(?:;\s*url\s*=\s*(.*?)\s*)?", value, re.IGNORECASE
    )
    if not match:
        raise ValueError("Invalid Refresh header")
    delay, target = match.groups()
    if target is None:
        return delay
    if target.startswith(("'", '"')):
        if len(target) < 2 or target[-1] != target[0]:
            raise ValueError("Invalid quoted Refresh target")
        target = target[1:-1]
    rewritten = rewrite_url(
        target,
        upstream,
        local_origin,
        explicit_scheme=explicit_scheme,
    )
    return f"{delay}; url={rewritten}"
