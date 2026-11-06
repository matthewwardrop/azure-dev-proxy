from __future__ import annotations

import hashlib
import hmac
import html
import os
import re
import secrets
import stat
import tempfile
import time
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote_plus, urlencode

from aiohttp import web

from .config import Config

TOKEN_PARAMETER = "azure-dev-proxy-token"
TOKEN_HEADER = "X-Azure-Dev-Proxy-Token"
LOGIN_PATH = "/:login"
SESSION_PATH = "/:session"
ROUTE_KEY = web.RequestKey("authenticated_route", str)
SESSION_KEY = web.RequestKey("new_session", bool)
HANDOFF_KEY = web.RequestKey("session_handoff", bool)
LOGIN_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
}


class ProxyAuthentication:
    """
    Shared-key access to the local proxy and host-bound browser sessions.

    A null key explicitly disables authentication. Session cookies remain valid
    across proxy restarts with the same key, hostname and port, until the browser
    discards them. These credentials do not isolate mutually untrusted processes
    running as the same operating-system user.
    """

    def __init__(self, token: str | None) -> None:
        if token is not None and (
            not token
            or len(token) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in token)
        ):
            raise ValueError(
                "The proxy authentication key must be nonempty and contain no controls"
            )
        self._key = token.encode("utf-8") if token is not None else None
        self._handoffs: dict[str, tuple[str, str, float]] = {}

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        token: str | None = None,
        disabled: bool = False,
    ) -> ProxyAuthentication:
        """
        Load a saved key, creating a private random key file if it is missing.

        Args:
            path: Key file; generated files are readable only by their owner
                on POSIX. Existing POSIX files must belong to the current user.
                Windows uses the containing directory's inherited ACL.
            token: Explicit key instead of a key file, or null to use the file.
            disabled: Disable authentication without reading or creating a key.
        """
        if disabled or token is not None:
            return cls(None if disabled else token)
        if path.is_symlink():
            raise ValueError("The authentication key file must not be a symbolic link")
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent
            ) as temporary:
                temporary.write(secrets.token_urlsafe(32) + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
                try:
                    os.link(temporary.name, path)
                except FileExistsError:
                    pass
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        # Validate and read the same inode even if the pathname is replaced.
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("The authentication key file must be a regular file")
            if os.name != "nt":
                if metadata.st_uid != os.geteuid():
                    raise ValueError(
                        "The authentication key file must belong to the current user"
                    )
                if metadata.st_mode & 0o077:
                    raise ValueError(
                        "The authentication key file must be accessible only to its owner"
                    )
            with os.fdopen(descriptor, encoding="utf-8", closefd=False) as key_file:
                return cls(key_file.read().rstrip("\r\n"))
        finally:
            os.close(descriptor)

    @property
    def enabled(self) -> bool:
        """Whether access requires a key or an authenticated browser session."""
        return self._key is not None

    def login_url(self, origin: str) -> str:
        """Return a key-bearing startup URL, or the plain UI URL when disabled."""
        origin = Config.normalize_origin(origin)
        if self._key is None:
            return origin + "/"
        return origin + "/?" + urlencode({TOKEN_PARAMETER: self._key.decode("utf-8")})

    @staticmethod
    def strip_query_token(raw_path: str) -> tuple[str, tuple[str, ...]]:
        """Remove reserved query fields, preserving other parameters' raw encoding."""
        path, separator, query = raw_path.partition("?")
        if not separator:
            return raw_path, ()
        remaining = []
        tokens = []
        for field in query.split("&"):
            key, _, value = field.partition("=")
            if unquote_plus(key) == TOKEN_PARAMETER:
                tokens.append(unquote_plus(value))
            else:
                remaining.append(field)
        return path + ("?" + "&".join(remaining) if remaining else ""), tuple(tokens)

    def _matches(self, token: str) -> bool:
        return self._key is not None and secrets.compare_digest(
            self._key,
            token.encode("utf-8"),
        )

    @staticmethod
    def _cookie_name(request: web.Request) -> str:
        return f"aad-dev-proxy-session-{request.url.port}"

    def _signature(self, request: web.Request, nonce: str) -> str:
        if self._key is None:
            raise RuntimeError("Authentication is disabled")
        origin = Config.normalize_origin("http://" + request.headers["Host"])
        return hmac.new(
            self._key,
            f"browser-session:{origin}:{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()

    def _has_session(self, request: web.Request) -> bool:
        cookie = request.cookies.get(self._cookie_name(request), "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}\.[a-f0-9]{64}", cookie):
            return False
        nonce, signature = cookie.split(".")
        return secrets.compare_digest(signature, self._signature(request, nonce))

    def prepare_response(
        self, request: web.Request, response: web.StreamResponse
    ) -> None:
        """Apply private caching and issue a host-only, HttpOnly session if requested."""
        if not self.enabled:
            return
        response.headers["Cache-Control"] = "no-store"
        if request.get(SESSION_KEY, False):
            nonce = secrets.token_urlsafe(32)
            response.set_cookie(
                self._cookie_name(request),
                nonce + "." + self._signature(request, nonce),
                httponly=True,
                samesite="Lax",
                path="/",
            )
            # aiohttp has already serialized cookies when response-prepare hooks run.
            response.headers.add(
                "Set-Cookie",
                response.cookies[self._cookie_name(request)].OutputString(),
            )

    def login_page(
        self, request: web.Request, *, invalid: bool = False
    ) -> web.Response:
        """Prompt for a key without exposing it in the document or return URL."""
        page = (
            files("azure_dev_proxy")
            .joinpath("static/login.html")
            .read_text(encoding="utf-8")
        )
        page = page.replace(
            "__ERROR__", "Invalid authentication key." if invalid else ""
        )
        page = page.replace("__NEXT__", html.escape(request[ROUTE_KEY], quote=True))
        return web.Response(
            text=page, status=401, content_type="text/html", headers=LOGIN_HEADERS
        )

    @staticmethod
    def _redirect(location: str) -> web.Response:
        return web.Response(
            status=303,
            headers={
                **LOGIN_HEADERS,
                "Referrer-Policy": "origin",
                "Location": location,
            },
        )

    @staticmethod
    def _return_path(value: object) -> str:
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or value.startswith("//")
            or any(
                char == "\\" or ord(char) <= 32 or ord(char) == 127 for char in value
            )
        ):
            raise web.HTTPBadRequest(text="Invalid login return path\n")
        return ProxyAuthentication.strip_query_token(value)[0]

    @staticmethod
    def _other_origin(request: web.Request) -> str:
        host = "127.0.0.1" if request.url.host == "localhost" else "localhost"
        return f"http://{host}:{request.url.port}"

    def is_handoff(self, request: web.Request, query_tokens: tuple[str, ...]) -> bool:
        """Recognize a destination-bound GET handoff before browser-origin checks."""
        if (
            not self.enabled
            or len(query_tokens) != 1
            or request.method not in {"GET", "HEAD"}
        ):
            return False
        if request.headers.get("Sec-Fetch-Mode") not in {None, "navigate"}:
            return False
        if request.headers.get("Sec-Fetch-Dest") not in {None, "document"}:
            return False
        token = query_tokens[0]
        expected = self._handoffs.get(token)
        if expected is None:
            return False
        origin, route, expires = expected
        if (
            time.monotonic() >= expires
            or Config.normalize_origin("http://" + request.headers["Host"]) != origin
            or request[ROUTE_KEY] != route
        ):
            return False
        return True

    def _consume_handoff(self, request: web.Request, token: str) -> bool:
        if not self.is_handoff(request, (token,)):
            return False
        del self._handoffs[token]
        return True

    @staticmethod
    def _continue_navigation(request: web.Request) -> web.Response:
        # A fresh document avoids form-action redirect restrictions and Origin:null.
        route = html.escape(request[ROUTE_KEY], quote=True)
        return web.Response(
            text=(
                '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<meta http-equiv="refresh" content="0;url={route}">'
                "<title>Signing in - Azure Dev Proxy</title></head>"
                f'<body><a href="{route}">Continue</a></body></html>'
            ),
            content_type="text/html",
            headers=LOGIN_HEADERS,
        )

    def _handoff(self, request: web.Request) -> web.Response:
        values = request.query.getall("next", [])
        if len(values) != 1:
            raise web.HTTPBadRequest(text="A single session return path is required\n")
        route = self._return_path(values[0])
        if route.partition("?")[0] == SESSION_PATH:
            raise web.HTTPBadRequest(
                text="Recursive session handoff is not supported\n"
            )
        return self.handoff_response(request, route)

    def handoff_response(self, request: web.Request, route: str) -> web.Response:
        """Pair the other loopback hostname for an already-authenticated GET."""
        now = time.monotonic()
        self._handoffs = {
            token: entry for token, entry in self._handoffs.items() if entry[2] > now
        }
        if len(self._handoffs) >= 1024:
            del self._handoffs[next(iter(self._handoffs))]
        token = "session-" + secrets.token_urlsafe(32)
        origin = self._other_origin(request)
        self._handoffs[token] = (origin, route, now + 60)
        separator = "&" if "?" in route else "?"
        return self._redirect(
            origin + route + separator + urlencode({TOKEN_PARAMETER: token})
        )

    async def authorize(
        self,
        request: web.Request,
        query_tokens: tuple[str, ...],
    ) -> web.Response | None:
        """Authenticate before local management, GraphiQL rendering or forwarding."""
        if not self.enabled:
            return None
        if request.path == SESSION_PATH and request.method not in {"GET", "HEAD"}:
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "HEAD"])
        if request.path == LOGIN_PATH:
            if request.method != "POST":
                raise web.HTTPMethodNotAllowed(request.method, ["POST"])
            origin = request.headers.get("Origin")
            if origin is not None and origin != "http://" + request.headers["Host"]:
                raise web.HTTPForbidden(text="Local same-origin login required\n")
            if request.content_type != "application/x-www-form-urlencoded":
                raise web.HTTPBadRequest(text="A URL-encoded login form is required\n")
            form = await request.post()
            tokens = form.getall("token", [])
            request[ROUTE_KEY] = self._return_path(form.get("next", "/"))
            if (
                len(tokens) != 1
                or not isinstance(tokens[0], str)
                or not self._matches(tokens[0])
            ):
                return self.login_page(request, invalid=True)
            request[SESSION_KEY] = True
            return self._continue_navigation(request)
        header_tokens = request.headers.getall(TOKEN_HEADER, [])
        if len(query_tokens) > 1 or len(header_tokens) > 1:
            raise web.HTTPBadRequest(text="Supply a single proxy authentication key\n")
        supplied = (*query_tokens, *header_tokens)
        if supplied:
            valid = all(self._matches(token) for token in header_tokens) and all(
                self._matches(token) or self._consume_handoff(request, token)
                for token in query_tokens
            )
        else:
            valid = self._has_session(request)
        if not valid:
            if request.method in {"GET", "HEAD"}:
                if (
                    not supplied
                    and request.path != SESSION_PATH
                    and request.headers.get("Sec-Fetch-Mode") == "navigate"
                    and request.headers.get("Sec-Fetch-Dest") == "document"
                ):
                    return self._redirect(
                        self._other_origin(request)
                        + SESSION_PATH
                        + "?"
                        + urlencode({"next": request[ROUTE_KEY]}),
                    )
                return self.login_page(request, invalid=bool(supplied))
            return web.Response(
                status=401,
                text="Proxy authentication required\n",
                headers=LOGIN_HEADERS,
            )
        if query_tokens:
            request[SESSION_KEY] = True
            if request.method in {"GET", "HEAD"}:
                if request.get(HANDOFF_KEY, False):
                    return self._continue_navigation(request)
                if request.headers.get("Sec-Fetch-Mode") == "navigate":
                    return self._redirect(request[ROUTE_KEY])
        if request.path == SESSION_PATH:
            return self._handoff(request)
        return None
