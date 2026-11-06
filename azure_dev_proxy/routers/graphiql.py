from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from importlib.resources import files

from aiohttp import web
from yarl import URL

from ..auth import ROUTE_KEY
from ._base import Router
from .reverse_proxy import REVERSE_PROXY_KEY
from .utils import GRAPHQL_PREFIX, parse_target, validate_destination


class GraphiQL(Router):
    """GraphiQL pages and POST forwarding for an HTTP(S) API destination."""

    def register(self, app: web.Application) -> None:
        """Register the GraphiQL destination path before special-path fallbacks."""
        app.router.add_route("*", GRAPHQL_PREFIX + "{destination:.*}", self.handle)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        """Serve the GraphiQL page for GET/HEAD, or forward a POST to its API."""
        try:
            route = GraphQLRoute.parse(request[ROUTE_KEY])
            if route is None:
                raise ValueError("Invalid GraphiQL prefix")
        except ValueError:
            raise web.HTTPBadRequest(text="Invalid destination route\n") from None
        call = validate_destination(request, route.target, port=self.proxy.port)
        if request.method in {"GET", "HEAD"}:
            call.source = "graphiql-ui"
            return route.page()
        if request.method != "POST":
            raise web.HTTPMethodNotAllowed(request.method, ["GET", "HEAD", "POST"])
        return await request.app[REVERSE_PROXY_KEY].forward(
            request, route.target, call, explicit_scheme=True
        )


@dataclass(frozen=True)
class GraphQLRoute:
    """
    A local GraphiQL page for an HTTP(S) API.

    Attributes:
        target: HTTP(S) API URL preserving the encoded path and query.
    """

    target: URL

    @classmethod
    def parse(cls, raw_path: str) -> GraphQLRoute | None:
        """Parse GraphiQL routes with HTTPS by default, or return None for other paths."""
        if not raw_path.startswith(GRAPHQL_PREFIX):
            return None
        value = raw_path[len(GRAPHQL_PREFIX) :]
        if (
            any(ord(char) <= 32 or ord(char) == 127 for char in raw_path)
            or "#" in raw_path
            or "\\" in raw_path
        ):
            raise ValueError("Invalid GraphQL route")
        return cls(parse_target("/" + value))

    def page(self) -> web.Response:
        """Render the bundled GraphiQL UI without contacting the upstream API."""
        nonce = secrets.token_urlsafe(24)
        endpoint = json.dumps(str(self.target), ensure_ascii=True).replace(
            "<", "\\u003c"
        )
        template = (
            files("azure_dev_proxy")
            .joinpath("static/graphiql.html")
            .read_text(encoding="utf-8")
        )
        page = template.replace("__NONCE__", nonce).replace(
            "__TRANSPORT_URL__", endpoint
        )
        return web.Response(
            text=page,
            content_type="text/html",
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": (
                    f"default-src 'none'; script-src 'nonce-{nonce}' https://esm.sh data:; "
                    "style-src 'unsafe-inline' https://esm.sh; connect-src 'self' https://esm.sh; "
                    "worker-src blob: https://esm.sh; img-src data:; font-src https://esm.sh data:; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
                ),
            },
        )
