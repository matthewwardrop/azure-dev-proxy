from __future__ import annotations

import logging
from collections.abc import AsyncIterator

from aiohttp import ClientError, web
from multidict import CIMultiDict
from yarl import URL

from ..auth import ROUTE_KEY, TOKEN_HEADER, ProxyAuthentication
from ._base import Router
from .management import MANAGEMENT_KEY
from .utils import (
    ProxyCall,
    parse_target,
    rewrite_refresh,
    rewrite_url,
    validate_destination,
)

LOG = logging.getLogger("azure_dev_proxy.proxy")
HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class ReverseProxy(Router):
    """Streaming HTTP(S) forwarding through the proxy's owned upstream session."""

    def register(self, app: web.Application) -> None:
        """Register ordinary forwarding after all local endpoints."""
        app[REVERSE_PROXY_KEY] = self
        app.router.add_route("*", "/{destination:.*}", self.handle)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        """Parse and forward an ordinary destination using its raw route bytes."""
        try:
            target = parse_target(request[ROUTE_KEY])
        except ValueError:
            raise web.HTTPBadRequest(text="Invalid destination route\n") from None
        call = validate_destination(request, target, port=self.proxy.port)
        return await self.forward(request, target, call)

    async def forward(
        self,
        request: web.Request,
        target: URL,
        call: ProxyCall,
        *,
        explicit_scheme: bool = False,
    ) -> web.StreamResponse:
        """
        Stream a validated HTTP(S) destination through the upstream session.

        Args:
            request: Authenticated request approved by the browser policy.
            target: Parsed destination, already checked for self-loops.
            call: Request log context updated with the acquisition result.
            explicit_scheme: Force explicit HTTPS in rewritten navigation,
                as GraphiQL POSTs require. Otherwise preserve the ordinary
                route's scheme style. HTTP always retains its scheme.
        """
        proxy = self.proxy
        origin = str(target.origin())
        headers = filtered_headers(CIMultiDict(request.headers), request=True)
        if "Referer" in headers:
            referer, _ = ProxyAuthentication.strip_query_token(headers["Referer"])
            headers["Referer"] = referer
        headers["Host"] = target.raw_authority
        resource = request.app[MANAGEMENT_KEY].resource_for(origin, proxy.config)
        call.source = "non-https" if target.scheme != "https" else "not-allowlisted"
        if resource is not None:
            call.source = "acquisition-interrupted"
            result = await proxy.tokens.get_with_status(origin, resource)
            call.source = result.source
            call.token = result.token is not None
            if result.token is not None:
                headers["Authorization"] = f"Bearer {result.token}"
        call.emit(request.method)
        if proxy.session is None:
            raise RuntimeError("Proxy session has not started")
        response: web.StreamResponse | None = None
        explicit_scheme = explicit_scheme or request[ROUTE_KEY][1:].lower().startswith(
            ("http://", "https://")
        )
        try:
            async with proxy.session.request(
                request.method,
                target,
                headers=headers,
                data=_body_chunks(request) if request.can_read_body else None,
                allow_redirects=False,
                ssl=proxy.tls,
            ) as upstream:
                response_headers = filtered_headers(
                    CIMultiDict(upstream.headers), request=False
                )
                try:
                    for name in ("Location", "Refresh"):
                        values = response_headers.getall(name, [])
                        if values:
                            del response_headers[name]
                            for value in values:
                                rewritten = (
                                    rewrite_url(
                                        value,
                                        target,
                                        proxy.local_origin,
                                        explicit_scheme=explicit_scheme,
                                    )
                                    if name == "Location"
                                    else rewrite_refresh(
                                        value,
                                        target,
                                        proxy.local_origin,
                                        explicit_scheme=explicit_scheme,
                                    )
                                )
                                response_headers.add(name, rewritten)
                except ValueError:
                    LOG.warning(
                        "Unsupported or invalid navigation header from %s", origin
                    )
                    raise web.HTTPBadGateway(
                        text="Unsupported or invalid upstream navigation target\n"
                    ) from None
                if upstream.status == 101:
                    raise web.HTTPBadGateway(
                        text="Upstream protocol upgrades are not supported\n"
                    )
                response = web.StreamResponse(
                    status=upstream.status, headers=response_headers
                )
                await response.prepare(request)
                async for chunk in upstream.content.iter_chunked(65536):
                    await response.write(chunk)
                await response.write_eof()
                return response
        except (ClientError, OSError, TimeoutError) as error:
            LOG.warning("Upstream failure for %s (%s)", origin, type(error).__name__)
            if response is not None and response.prepared:
                if request.transport is not None:
                    request.transport.close()
                return response
            if isinstance(error, TimeoutError):
                raise web.HTTPGatewayTimeout(text="Upstream timed out\n") from None
            raise web.HTTPBadGateway(text="Upstream connection failed\n") from None


def filtered_headers(headers: CIMultiDict[str], *, request: bool) -> CIMultiDict[str]:
    """Strip hop-by-hop headers and credentials while retaining duplicate fields."""
    blocked = HOP_HEADERS | {"cookie", "set-cookie"}
    if request:
        blocked |= {"host", "authorization", TOKEN_HEADER.lower()}
    for connection in headers.getall("Connection", []):
        blocked.update(part.strip().lower() for part in connection.split(","))
    return CIMultiDict(
        (key, value) for key, value in headers.items() if key.lower() not in blocked
    )


async def _body_chunks(request: web.Request) -> AsyncIterator[bytes]:
    async for chunk in request.content.iter_chunked(65536):
        yield chunk


REVERSE_PROXY_KEY = web.AppKey("reverse_proxy", ReverseProxy)
