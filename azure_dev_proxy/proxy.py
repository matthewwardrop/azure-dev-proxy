from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import signal
import socket
import ssl
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from functools import cached_property
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, DummyCookieJar, web

from .auth import HANDOFF_KEY, ROUTE_KEY, ProxyAuthentication
from .config import Config
from .idle_timer import IdleTracker
from .listeners import LoopbackListeners
from .routers import Router
from .routers.graphiql import GraphiQL, GraphQLRoute
from .routers.management import Management
from .routers.reverse_proxy import ReverseProxy
from .routers.utils import CALL_KEY, ProxyCall, log_url, parse_target
from .tokens import AzureCLI, TokenProvider

LOG = logging.getLogger(__name__)
HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


class SanitizedServerErrors(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # aiohttp parser errors can otherwise include raw request credentials.
        category = (
            record.exc_info[0].__name__
            if record.exc_info and record.exc_info[0]
            else record.levelname
        )
        record.msg = "HTTP server failure (%s)"
        record.args = (category,)
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


SERVER_LOG = logging.getLogger("azure_dev_proxy.http")
SERVER_LOG.addFilter(SanitizedServerErrors())


class Proxy:
    """
    A streaming HTTP(S) proxy using Azure CLI authentication only for HTTPS.

    Attributes:
        app: Lazily created, cached aiohttp application with routing, middleware
            and lifecycle hooks installed, ready for a runner or server.
        port: Local loopback port shared by the UI and forwarding endpoints.
            Defaults to zero before binding; serve sets the effective port.
        config: Active routing settings loaded from disk or supplied by the caller.
            Persisted edits replace this only after a successful file write.
        config_path: Configuration file for saving rules, or null when persistence
            is unavailable.
        read_timeout: Upstream read-idle timeout in seconds, not a total timeout.
        authentication: Local access-key and browser-session authentication.
        activity: Request activity used for automatic idle shutdown.
        routers: Router classes in registration order, with ordinary forwarding
            last. Instances are created only when app is first accessed.
    """

    routers: list[type[Router]] = [GraphiQL, Management, ReverseProxy]

    def __init__(
        self,
        tokens: TokenProvider | None = None,
        *,
        port: int = 0,
        config: Config | None = None,
        tls: ssl.SSLContext | bool = True,
        read_timeout: float = 60,
        authentication: ProxyAuthentication | None = None,
        config_path: Path | None = None,
        az_path: str = "az",
        token: str | None = None,
        token_file: Path | None = None,
        no_auth: bool = False,
    ) -> None:
        """
        Configure a proxy with default services or caller-supplied dependencies.

        Args:
            tokens: Token provider, or null to create one using Azure CLI.
            port: Initial loopback port; serve sets the bound port.
            config: Routing settings, or null to load the configuration file.
            tls: Upstream TLS context, or whether to verify certificates.
            read_timeout: Upstream read-idle timeout in seconds.
            authentication: Local authentication, or null to initialize it.
            config_path: Configuration file; defaults to the native user path
                when config is omitted. Supplied settings without a path are
                memory-only and use an ephemeral key by default.
            az_path: Azure CLI executable used when tokens is omitted.
            token: Explicit proxy key, overriding AZURE_DEV_PROXY_TOKEN.
            token_file: Key file, overriding the environment variable. Defaults
                to auth-token beside the configuration file.
            no_auth: Disable authentication when authentication is omitted.
        """
        if config is None:
            config_path = (
                config_path if config_path is not None else Config.default_path()
            )
            config = Config.load(config_path)
        if config_path is not None:
            LOG.info("Using configuration at %s", config_path)
        if authentication is None:
            token_path = token_file
            if token_path is None and config_path is not None:
                token_path = config_path.with_name("auth-token")
            if token is None and token_file is None and not no_auth:
                token = os.environ.get("AZURE_DEV_PROXY_TOKEN")
            if token_path is not None:
                authentication = ProxyAuthentication.load(
                    token_path, token=token, disabled=no_auth
                )
            elif no_auth:
                authentication = ProxyAuthentication(None)
            else:
                authentication = ProxyAuthentication(
                    token if token is not None else secrets.token_urlsafe(32)
                )
            if not authentication.enabled:
                warning = (
                    "WARNING: Proxy authentication is disabled "
                    "(other users of this machine, including applications, "
                    "can use this proxy without authorization)"
                )
                if sys.stderr.isatty():
                    warning = f"\x1b[31m{warning}\x1b[0m"
                print(warning, file=sys.stderr)
            elif token is None and token_path is not None:
                LOG.info("Proxy authentication key file: %s", token_path)
        self.tokens = (
            tokens if tokens is not None else TokenProvider(AzureCLI(az_path).acquire)
        )
        self.port = port
        self.config = config
        self.config_path = config_path
        self.tls = tls
        self.read_timeout = read_timeout
        self.authentication = authentication
        self.session: ClientSession | None = None
        self.activity = IdleTracker()

    @cached_property
    def app(self) -> web.Application:
        """The configured aiohttp application, created and cached on first access."""
        app = web.Application(
            middlewares=[self._track_request],
            client_max_size=16384,
            handler_args={
                "handler_cancellation": True,
                "logger": SERVER_LOG,
                "auto_decompress": False,
            },
        )
        app.cleanup_ctx.append(self.lifecycle)
        app.on_response_prepare.append(self._prepare_response)
        for router in self.routers:
            router(self).register(app)
        return app

    @property
    def local_origin(self) -> str:
        """The read-only IP-loopback origin used for forwarded navigation."""
        return f"http://127.0.0.1:{self.port}"

    def serve(self, port: int, *, idle_timeout: float = 0) -> None:
        """
        Serve a loopback port until signalled or the enabled idle timeout.

        Owns the listeners and event loop and blocks until shutdown. Inherited
        systemd sockets are adopted before the event loop is created. Call
        outside a running event loop. Sets port to the effective listener port.

        Socket activation is optional. A separately configured systemd socket
        unit can start a new process when a connection arrives after idle exit.
        Direct startup, including normal Windows startup, has no
        connection-triggered restart. This proxy is not a Windows Service and
        does not integrate with the Windows Service Control Manager.

        Active requests and streams prevent idle exit. Graceful stopping uses
        the platform's supported signal handling, including console Ctrl+C on
        Windows. The proxy does not arrange its own restart after stopping.
        Stopping cleans up the application and its owned token acquisitions.

        Args:
            port: Loopback TCP port shared by IPv4 and available IPv6 listeners.
                Zero selects a free port for direct startup; inherited sockets
                must match the specified port.
            idle_timeout: Inactive seconds before process exit when positive.
                Defaults to zero, disabling automatic idle shutdown.
        """
        with LoopbackListeners(port) as listeners:
            self.port = listeners[0].getsockname()[1]
            asyncio.run(self._serve(listeners, idle_timeout=idle_timeout))

    async def _serve(
        self, listeners: list[socket.socket], *, idle_timeout: float = 0
    ) -> None:
        """Run the application on owned sockets and clean up on shutdown."""
        runner = web.AppRunner(self.app, access_log=None, shutdown_timeout=35)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        tasks: list[asyncio.Task[None] | asyncio.Task[bool]] = []
        signals = (signal.SIGINT, signal.SIGTERM)
        registered_signals = []
        fallback_signals = {}
        try:
            await runner.setup()
            for listener in listeners:
                await web.SockSite(runner, listener).start()
            for signum in signals:
                try:
                    loop.add_signal_handler(signum, stop.set)
                    registered_signals.append(signum)
                except NotImplementedError:
                    fallback_signals[signum] = signal.signal(
                        signum,
                        lambda *_: loop.call_soon_threadsafe(stop.set),
                    )
            print(
                f"Azure proxy listening at http://localhost:{self.port}",
                flush=True,
            )
            if self.authentication.enabled:
                for host in ("localhost", "127.0.0.1"):
                    LOG.info(
                        "%s",
                        self.authentication.login_url(f"http://{host}:{self.port}"),
                    )
            tasks = [asyncio.create_task(stop.wait())]
            idle = None
            if idle_timeout > 0:
                idle = asyncio.create_task(self.activity.wait_for_idle(idle_timeout))
                tasks.append(idle)
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if idle is not None and idle.done():
                idle.result()
                LOG.info("Idle timeout reached; shutting down")
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for signum in registered_signals:
                loop.remove_signal_handler(signum)
            for signum, handler in fallback_signals.items():
                signal.signal(signum, handler)
            await runner.cleanup()

    async def lifecycle(self, app: web.Application) -> AsyncIterator[None]:
        async with ClientSession(
            cookie_jar=DummyCookieJar(),
            auto_decompress=False,
            timeout=ClientTimeout(
                total=None, sock_connect=10, sock_read=self.read_timeout
            ),
            skip_auto_headers={"Accept-Encoding", "User-Agent", "Content-Type"},
        ) as session:
            self.session = session
            try:
                yield
            finally:
                await self.tokens.close()
                self.session = None

    def validate_client(self, request: web.Request) -> None:
        hosts = request.headers.getall("Host", [])
        if len(hosts) != 1:
            raise web.HTTPBadRequest(text="A single local Host header is required\n")
        try:
            host = urlsplit("http://" + hosts[0])
            valid = Config.normalize_host(host.hostname or "") in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
            valid = valid and (host.port or 80) == self.port
            valid = valid and not host.username and not host.password and not host.path
            valid = valid and not host.query and not host.fragment
        except ValueError:
            valid = False
        if not valid:
            raise web.HTTPBadRequest(text="Invalid local Host header\n")
        if len(request.headers.getall("Origin", [])) > 1:
            raise web.HTTPBadRequest(text="A single Origin header is required\n")
        if request.method == "CONNECT":
            raise web.HTTPMethodNotAllowed(request.method, HTTP_METHODS)
        if request.headers.get("Upgrade"):
            raise web.HTTPBadRequest(text="Protocol upgrades are not supported\n")

    def is_trusted_origin(self, origin: str) -> bool:
        """Return whether a browser origin may use the forwarding proxy."""
        try:
            origin = Config.normalize_origin(origin)
        except ValueError:
            return False
        local = {
            Config.normalize_origin(f"http://{host}:{self.port}")
            for host in ("localhost", "127.0.0.1", "[::1]")
        }
        return origin in local or origin in self.config.trusted_origins

    def validate_browser(self, request: web.Request) -> None:
        """Reject untrusted browser requests before forwarding or acquiring tokens."""
        if request.get(HANDOFF_KEY, False):
            return
        origin = request.headers.get("Origin")
        if origin is not None:
            allowed = self.is_trusted_origin(origin)
        elif request.headers.get("Referer") is not None:
            try:
                referer = urlsplit(request.headers["Referer"])
                allowed = self.is_trusted_origin(f"{referer.scheme}://{referer.netloc}")
            except ValueError:
                allowed = False
        else:
            site = request.headers.get("Sec-Fetch-Site")
            direct_navigation = (
                site == "none"
                and request.method in {"GET", "HEAD"}
                and request.headers.get("Sec-Fetch-Mode") == "navigate"
                and request.headers.get("Sec-Fetch-Dest") == "document"
                and request.headers.get("Sec-Fetch-User") == "?1"
            )
            browser = any(
                name.lower().startswith("sec-fetch-") for name in request.headers
            )
            allowed = not browser or site == "same-origin" or direct_navigation
        if not allowed:
            raise web.HTTPForbidden(
                text="Browser origin is not trusted for forwarding\n"
            )

    async def _prepare_response(
        self, request: web.Request, response: web.StreamResponse
    ) -> None:
        self.authentication.prepare_response(request, response)
        if Management.is_local_path(request.path):
            return
        origin = request.headers.get("Origin")
        if origin and self.is_trusted_origin(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            exposed = {}
            for value in (
                *response.headers.getall("Access-Control-Expose-Headers", []),
                "Location, Refresh",
            ):
                for name in value.split(","):
                    name = name.strip()
                    if name:
                        exposed.setdefault(name.lower(), name)
            response.headers["Access-Control-Expose-Headers"] = ", ".join(
                exposed.values()
            )
        vary = {
            value.strip().lower()
            for header in response.headers.getall("Vary", [])
            for value in header.split(",")
        }
        if "*" not in vary:
            for name in (
                "Origin",
                "Referer",
                "Sec-Fetch-Site",
                "Sec-Fetch-Mode",
                "Sec-Fetch-Dest",
                "Sec-Fetch-User",
            ):
                if name.lower() not in vary:
                    response.headers.add("Vary", name)

    async def _route_request(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        route, query_tokens = ProxyAuthentication.strip_query_token(request.raw_path)
        request[ROUTE_KEY] = route
        call = ProxyCall(log_url(self.local_origin + route))
        request[CALL_KEY] = call
        try:
            self.validate_client(request)
            request[HANDOFF_KEY] = self.authentication.is_handoff(request, query_tokens)
            if Management.is_local_path(request.path):
                Management.validate_browser(request)
                response = await self.authentication.authorize(request, query_tokens)
                if response is not None:
                    return response
                return await handler(request)
            self.validate_browser(request)
            if (
                request.method == "OPTIONS"
                and request.headers.get("Origin")
                and request.headers.get("Access-Control-Request-Method")
            ):
                try:
                    graphql = GraphQLRoute.parse(route)
                    target = graphql.target if graphql else parse_target(route)
                except ValueError:
                    raise web.HTTPBadRequest(
                        text="Invalid destination route\n"
                    ) from None
                call.url = log_url(str(target))
                call.source = "cors-preflight"
                method = request.headers["Access-Control-Request-Method"]
                if method not in HTTP_METHODS:
                    raise web.HTTPMethodNotAllowed(method, HTTP_METHODS)
                requested_headers = [
                    name.strip()
                    for name in request.headers.get(
                        "Access-Control-Request-Headers", ""
                    ).split(",")
                    if name.strip()
                ]
                if any(
                    not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    for name in requested_headers
                ):
                    raise web.HTTPBadRequest(
                        text="Invalid CORS requested header name\n"
                    )
                headers = {"Access-Control-Allow-Methods": ", ".join(HTTP_METHODS)}
                if requested_headers:
                    headers["Access-Control-Allow-Headers"] = ", ".join(
                        requested_headers
                    )
                if (
                    request.headers.get("Access-Control-Request-Private-Network")
                    == "true"
                ):
                    headers["Access-Control-Allow-Private-Network"] = "true"
                return web.Response(status=204, headers=headers)
            response = await self.authentication.authorize(request, query_tokens)
            if response is not None:
                return response
            if Management.is_edit_host(request.headers["Host"]):
                try:
                    if GraphQLRoute.parse(route) is None:
                        parse_target(route)
                except ValueError:
                    raise web.HTTPBadRequest(
                        text="Invalid destination route\n"
                    ) from None
                if self.authentication.enabled and request.method in {"GET", "HEAD"}:
                    return self.authentication.handoff_response(request, route)
                return web.Response(
                    status=307,
                    text="Forwarding uses the read-only loopback origin\n",
                    headers={
                        "Location": self.local_origin + route,
                        "Cache-Control": "no-store",
                    },
                )
            return await handler(request)
        finally:
            call.emit(request.method)

    @web.middleware
    async def _track_request(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        with self.activity.request():
            return await self._route_request(request, handler)
