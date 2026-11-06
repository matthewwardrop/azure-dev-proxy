from __future__ import annotations

import json
import secrets
from dataclasses import asdict
from importlib.resources import files
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from aiohttp import web

from ..auth import HANDOFF_KEY, LOGIN_PATH, SESSION_PATH
from ..config import Config, TokenRule
from ._base import Router
from .utils import GRAPHQL_PREFIX

if TYPE_CHECKING:
    from ..proxy import Proxy


API_PATH = "/:config"
PERSISTED_PATH = API_PATH + "/persisted"
SCRIPT_PATH = "/:app.js"
RESPONSE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}


class Management(Router):
    """Persisted routing configuration and process-lifetime temporary overrides."""

    def __init__(self, proxy: Proxy) -> None:
        super().__init__(proxy)
        self._overrides: dict[str, TokenRule] = {}
        self._csrf = secrets.token_hex(32)
        assets = files("azure_dev_proxy").joinpath("static")
        self._html = assets.joinpath("index.html").read_text(encoding="utf-8")
        self._script = assets.joinpath("app.js").read_text(encoding="utf-8")

    def register(self, app: web.Application) -> None:
        """Register local UI, config and auth paths, with a local special-path fallback."""
        app[MANAGEMENT_KEY] = self
        for path in (
            "/",
            API_PATH,
            PERSISTED_PATH,
            SCRIPT_PATH,
            LOGIN_PATH,
            SESSION_PATH,
        ):
            app.router.add_route("*", path, self.handle)
        app.router.add_route("*", "/:{endpoint:.*}", self.handle)

    @staticmethod
    def is_local_path(path: str) -> bool:
        """Return whether a path belongs to the local UI or management API."""
        return (
            path == "/" or path.startswith("/:") and not path.startswith(GRAPHQL_PREFIX)
        )

    @staticmethod
    def is_edit_host(host: str) -> bool:
        """Return whether an already validated Host names the editing origin."""
        return urlsplit("http://" + host).hostname == "localhost"

    def effective_rules(
        self, base_rules: tuple[TokenRule, ...]
    ) -> tuple[TokenRule, ...]:
        """Return overrides before base rules, each ordered by host specificity."""
        return (
            *sorted(self._overrides.values(), key=lambda rule: rule.priority),
            *sorted(base_rules, key=lambda rule: rule.priority),
        )

    def resource_for(self, origin: str, config: Config) -> str | None:
        """Return the token audience selected by the effective rules."""
        override = Config(tuple(self._overrides.values())).resource_for(origin)
        return config.resource_for(origin) if override is None else override

    def _snapshot(
        self,
        configuration: Config,
        *,
        editable: bool,
        persistence_available: bool,
    ) -> web.Response:
        effective = self.effective_rules(configuration.token_rules)
        return web.json_response(
            {
                "base_rules": [asdict(rule) for rule in configuration.token_rules],
                "overrides": [
                    asdict(rule) for rule in effective[: len(self._overrides)]
                ],
                "effective_rules": [asdict(rule) for rule in effective],
                "trusted_origins": list(configuration.trusted_origins),
                "override_lifetime": "Until process exit, including automatic idle shutdown.",
                "editable": editable,
                "persistence_available": persistence_available,
            },
            headers=RESPONSE_HEADERS,
        )

    @staticmethod
    def validate_browser(request: web.Request) -> None:
        """Require same-origin management requests, except deliberate UI navigation."""
        if request.get(HANDOFF_KEY, False):
            return
        host = request.headers["Host"]
        origin = request.headers.get("Origin")
        navigation = (
            request.method in {"GET", "HEAD"}
            and request.path in {"/", SESSION_PATH}
            and request.headers.get("Sec-Fetch-Mode") == "navigate"
            and request.headers.get("Sec-Fetch-Dest") == "document"
            and (
                request.path == SESSION_PATH
                or request.headers.get("Sec-Fetch-User") == "?1"
            )
        )
        if (
            origin is not None
            and origin != "http://" + host
            or request.headers.get("Sec-Fetch-Site") == "cross-site"
            and not navigation
        ):
            raise web.HTTPForbidden(text="Local same-origin access required\n")

    async def handle(self, request: web.Request) -> web.Response:
        """Serve local configuration without exposing tokens or forwarding CORS."""
        proxy = self.proxy
        self.validate_browser(request)
        host = request.headers["Host"]
        origin = request.headers.get("Origin")
        editable = self.is_edit_host(host)
        configuration = proxy.config
        persistence_available = proxy.config_path is not None
        if request.method in {"GET", "HEAD"} and request.path == "/":
            port = urlsplit("http://" + host).port or 80
            page = self._html
            for marker, value in {
                "__CSRF__": self._csrf if editable else "",
                "__EDITABLE__": "true" if editable else "false",
                "__EDIT_URL__": f"http://localhost:{port}/",
                "__FORWARD_ORIGIN__": f"http://127.0.0.1:{port}",
                "__EDITOR_HIDDEN__": "" if editable else "hidden",
                "__AUTH_WARNING_HIDDEN__": (
                    "hidden" if proxy.authentication.enabled else ""
                ),
            }.items():
                page = page.replace(marker, value)
            return web.Response(
                text=page, content_type="text/html", headers=RESPONSE_HEADERS
            )
        if request.method in {"GET", "HEAD"} and request.path == SCRIPT_PATH:
            return web.Response(
                text=self._script,
                content_type="text/javascript",
                headers=RESPONSE_HEADERS,
            )
        if request.path not in {API_PATH, PERSISTED_PATH}:
            if request.path in {"/", SCRIPT_PATH}:
                raise web.HTTPMethodNotAllowed(request.method, ["GET", "HEAD"])
            raise web.HTTPNotFound(text="Unknown management endpoint\n")
        persisted = request.path == PERSISTED_PATH
        if request.method in {"GET", "HEAD"} and not persisted:
            return self._snapshot(
                configuration,
                editable=editable,
                persistence_available=persistence_available,
            )
        if request.method not in {"POST", "DELETE"}:
            allowed = (
                ["POST", "DELETE"] if persisted else ["GET", "HEAD", "POST", "DELETE"]
            )
            raise web.HTTPMethodNotAllowed(request.method, allowed)
        csrf = request.headers.getall("X-Azure-Proxy-CSRF", [])
        if (
            not editable
            or origin is None
            or len(csrf) != 1
            or not secrets.compare_digest(csrf[0], self._csrf)
            or request.content_type != "application/json"
        ):
            raise web.HTTPForbidden(text="Same-origin JSON and CSRF token required\n")
        try:
            body = await request.read()
            value = json.loads(body)
            if persisted and (not isinstance(value, dict) or set(value) != {"host"}):
                raise ValueError("A persisted-rule operation requires a hostname")
            parsed = Config.parse({"token_rules": [value]})
        except (ValueError, UnicodeError, web.HTTPRequestEntityTooLarge):
            raise web.HTTPBadRequest(
                text="Invalid or oversized hostname/resource override\n"
            ) from None
        rule = parsed.token_rules[0]
        if persisted:
            if proxy.config_path is None:
                raise web.HTTPConflict(
                    text="No configuration file is available for persisted changes\n"
                )
            if request.method == "POST":
                promoted = self._overrides.get(rule.host)
                if promoted is None:
                    raise web.HTTPNotFound(
                        text="Temporary rule no longer exists; refresh and retry\n"
                    )
                rule = promoted
            try:
                updated = Config.update_rule(
                    proxy.config_path,
                    rule,
                    delete=request.method == "DELETE",
                )
            except PermissionError:
                raise web.HTTPForbidden(
                    text="The configuration file is read-only or not writable\n"
                ) from None
            except ValueError:
                raise web.HTTPConflict(
                    text="The configuration file contains invalid JSON or rules\n"
                ) from None
            except OSError:
                raise web.HTTPInternalServerError(
                    text="Could not update the configuration file\n"
                ) from None
            proxy.config = Config(updated.token_rules, proxy.config.trusted_origins)
            if request.method == "POST":
                self._overrides.pop(rule.host, None)
            configuration = proxy.config
        elif request.method == "DELETE":
            self._overrides.pop(rule.host, None)
        else:
            self._overrides[rule.host] = rule
        return self._snapshot(
            configuration,
            editable=editable,
            persistence_available=persistence_available,
        )


MANAGEMENT_KEY = web.AppKey("management", Management)
