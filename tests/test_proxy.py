from __future__ import annotations

import asyncio
import gzip
import json
import os
import shutil
import socket
import sys
import zlib
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import ClientSession, CookieJar, web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from multidict import CIMultiDict
from yarl import URL

from azure_dev_proxy.auth import ROUTE_KEY, ProxyAuthentication
from azure_dev_proxy.config import Config, TokenRule
from azure_dev_proxy.proxy import Proxy
from azure_dev_proxy.routers import Router
from azure_dev_proxy.routers.graphiql import GraphiQL, GraphQLRoute
from azure_dev_proxy.routers.management import MANAGEMENT_KEY, Management
from azure_dev_proxy.routers.reverse_proxy import (
    REVERSE_PROXY_KEY,
    ReverseProxy,
    filtered_headers,
)
from azure_dev_proxy.routers.utils import (
    GRAPHQL_PREFIX,
    ProxyCall,
    log_url,
    parse_target,
    rewrite_refresh,
    rewrite_url,
)
from azure_dev_proxy.tokens import AcquisitionError, AzureCLI, TokenProvider


class TestInitialization:
    async def test_default_services_load_config_and_reuse_saved_key(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "config.json"
        monkeypatch.setattr(Config, "default_path", staticmethod(lambda: path))
        monkeypatch.delenv("AZURE_DEV_PROXY_TOKEN", raising=False)
        acquire = AsyncMock(
            return_value=json.dumps(
                {"accessToken": "upstream-token", "expires_on": 4102444800}
            )
        )
        with patch("azure_dev_proxy.proxy.AzureCLI") as cli:
            cli.return_value.acquire = acquire
            proxy = Proxy(az_path="/custom/az")
            cli.assert_called_once_with("/custom/az")
        try:
            assert proxy.config == Config.defaults()
            assert proxy.config_path == path
            assert (tmp_path / "auth-token").is_file()
            assert (
                await proxy.tokens.get(
                    "https://api.example.com", "https://identity.example.com"
                )
                == "upstream-token"
            )
            acquire.assert_awaited_once_with("https://identity.example.com")
            restarted = Proxy(config_path=path)
            try:
                assert proxy.authentication.login_url(
                    "http://localhost:8080"
                ) == restarted.authentication.login_url("http://localhost:8080")
            finally:
                await restarted.tokens.close()
        finally:
            await proxy.tokens.close()

    @pytest.mark.parametrize(
        ("mode", "expected"),
        [
            ("environment", "environment-key"),
            ("explicit", "explicit-key"),
            ("file", "file-key"),
            ("disabled", None),
            ("disabled-memory", None),
        ],
    )
    def test_authentication_options_preserve_precedence(
        self, tmp_path, monkeypatch, mode, expected
    ):
        monkeypatch.setenv("AZURE_DEV_PROXY_TOKEN", "environment-key")
        key_path = tmp_path / "custom-key"
        if mode == "file":
            key_path.write_text("file-key\n", encoding="utf-8")
            key_path.chmod(0o600)
        proxy = Proxy(
            config=Config(()),
            config_path=None if mode == "disabled-memory" else tmp_path / "config.json",
            token="explicit-key" if mode == "explicit" else None,
            token_file=key_path if mode == "file" else None,
            no_auth=mode.startswith("disabled"),
        )
        url = proxy.authentication.login_url("http://localhost:8080")
        assert url == (
            f"http://localhost:8080/?azure-dev-proxy-token={expected}"
            if expected is not None
            else "http://localhost:8080/"
        )
        assert not (tmp_path / "auth-token").exists()


class TestRouting:
    @pytest.mark.parametrize(
        "route", ["foo.example/", "/foo.example/\x00", "/foo.example/\x7f"]
    )
    def test_routes_require_a_root_relative_path_without_controls(self, route):
        with pytest.raises(ValueError, match="Invalid proxy route"):
            parse_target(route)

    @pytest.mark.parametrize(
        ("headers", "message"),
        [
            ([], "single local Host"),
            (
                [("Host", "localhost:8080"), ("Host", "localhost:8080")],
                "single local Host",
            ),
            ([("Host", "localhost:foo")], "Invalid local Host"),
            (
                [
                    ("Host", "localhost:8080"),
                    ("Origin", "http://localhost:8080"),
                    ("Origin", "http://localhost:8080"),
                ],
                "single Origin",
            ),
        ],
    )
    def test_invalid_client_headers_are_rejected(self, headers, message):
        proxy = Proxy(TokenProvider(AsyncMock()), port=8080, config=Config(()))
        request = make_mocked_request("GET", "/", headers=CIMultiDict(headers))
        with pytest.raises(web.HTTPBadRequest) as error:
            proxy.validate_client(request)
        assert error.value.text is not None
        assert message in error.value.text

    def test_invalid_referrer_is_not_trusted(self):
        proxy = Proxy(TokenProvider(AsyncMock()), port=8080, config=Config(()))
        request = make_mocked_request(
            "GET", "/foo.example", headers={"Referer": "http://[foo"}
        )
        with pytest.raises(web.HTTPForbidden) as error:
            proxy.validate_browser(request)
        assert error.value.text is not None
        assert "Browser origin is not trusted" in error.value.text

    @pytest.mark.parametrize("vary", ["*", "Origin, Referer"])
    async def test_response_headers_preserve_existing_vary_and_ignore_empty_exposure(
        self, vary
    ):
        proxy = Proxy(
            TokenProvider(AsyncMock()),
            port=8080,
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        request = make_mocked_request(
            "GET",
            "/foo.example",
            headers={"Origin": "http://localhost:8080"},
        )
        response = web.Response(
            headers={"Vary": vary, "Access-Control-Expose-Headers": "Foo, ,foo"}
        )
        await proxy._prepare_response(request, response)
        assert (
            response.headers["Access-Control-Expose-Headers"]
            == "Foo, Location, Refresh"
        )
        assert (
            response.headers["Access-Control-Allow-Origin"] == "http://localhost:8080"
        )
        if vary == "*":
            assert response.headers.getall("Vary") == ["*"]
        else:
            values = [
                name.strip().lower()
                for value in response.headers.getall("Vary")
                for name in value.split(",")
            ]
            assert len(values) == len(set(values)) == 6
            assert set(values) == {
                "origin",
                "referer",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-dest",
                "sec-fetch-user",
            }

    def test_app_creation_is_deferred_and_reuses_the_configured_application(self):
        constructors = [MagicMock(wraps=router) for router in Proxy.routers]
        with (
            patch(
                "azure_dev_proxy.proxy.web.Application", wraps=web.Application
            ) as application,
            patch.object(Proxy, "routers", constructors),
        ):
            proxy = Proxy(
                TokenProvider(AsyncMock()),
                port=8080,
                config=Config(()),
                authentication=ProxyAuthentication(None),
            )
            application.assert_not_called()
            for constructor in constructors:
                constructor.assert_not_called()
            app = proxy.app
            assert proxy.app is app
            application.assert_called_once()
            for constructor in constructors:
                constructor.assert_called_once_with(proxy)
        assert list(app.middlewares) == [proxy._track_request]
        assert proxy.lifecycle in app.cleanup_ctx
        assert proxy._prepare_response in app.on_response_prepare
        handlers = [route.handler for route in app.router.routes()]
        graphiql = getattr(handlers[0], "__self__")
        assert isinstance(graphiql, GraphiQL)
        assert app[MANAGEMENT_KEY].handle in handlers
        assert handlers[-1] == app[REVERSE_PROXY_KEY].handle
        assert all(
            isinstance(router, Router) and router.proxy is proxy
            for router in (graphiql, app[MANAGEMENT_KEY], app[REVERSE_PROXY_KEY])
        )

    @pytest.mark.parametrize(
        ("path", "resource", "router"),
        [
            (
                "/:graphiql/example.com/a%2Fb?q=%2f",
                "/:graphiql/{destination}",
                GraphiQL,
            ),
            ("/", "/", Management),
            ("/:config", "/:config", Management),
            ("/:config/persisted", "/:config/persisted", Management),
            ("/:app.js", "/:app.js", Management),
            ("/:unknown", "/:{endpoint}", Management),
            (
                "/https://example.com/a%2Fb?q=%2f",
                "/{destination}",
                ReverseProxy,
            ),
        ],
    )
    async def test_app_selects_dedicated_routes_before_forwarding(
        self, path, resource, router
    ):
        proxy = Proxy(
            TokenProvider(AsyncMock()),
            port=8080,
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        match = await proxy.app.router.resolve(make_mocked_request("GET", path))
        matched_resource = match.route.resource
        assert matched_resource is not None
        assert matched_resource.canonical == resource
        instance = getattr(match.handler, "__self__")
        assert type(instance) is router
        assert instance.proxy is proxy

    def test_proxy_uses_supplied_config_without_loading_defaults(self):
        config = Config((), ("HTTPS://Example.COM:443",))
        with patch(
            "azure_dev_proxy.config.files",
            side_effect=AssertionError("Bundled defaults must not be loaded"),
        ):
            proxy = Proxy(
                TokenProvider(AsyncMock()),
                port=8080,
                config=config,
                authentication=ProxyAuthentication(None),
            )
        assert proxy.config is config
        assert type(proxy.app) is web.Application
        assert proxy.config.resource_for("https://foo.azure.net") is None
        assert proxy.is_trusted_origin("https://example.com")

    def test_graphql_routes_preserve_encoding_and_use_ordinary_proxy_paths(
        self, subtests
    ):
        for protocol, port, suffix in (
            ("", None, ""),
            ("", 443, ""),
            ("", 80, ":80"),
            ("", 8443, ":8443"),
            ("https", 443, ""),
            ("https", 80, ":80"),
            ("https", 8443, ":8443"),
            ("http", 80, ""),
            ("http", 443, ":443"),
        ):
            with subtests.test(protocol=protocol, port=port):
                scheme = protocol.upper() + "://" if protocol else ""
                authority = "Example.COM" + (f":{port}" if port is not None else "")
                destination = f"{scheme}{authority}/a%2Fb?q=%2f&q=two&empty=&"
                route = GraphQLRoute.parse(GRAPHQL_PREFIX + destination)
                assert route is not None
                target = f"{protocol or 'https'}://example.com{suffix}/a%2Fb?q=%2f&q=two&empty=&"
                assert str(route.target) == target
                assert route.target == parse_target("/" + destination)
        assert GraphQLRoute.parse("/https://example.com/graphql") is None
        for path in (
            "/graphql://host/",
            "/graphqls://host/",
            "/_graphql/transport/graphql://host/",
        ):
            assert GraphQLRoute.parse(path) is None
        for path in (
            "/:graphiql/",
            "/:graphiql/user@host/",
            "/:graphiql/host:0/",
            "/:graphiql/http://",
            "/:graphiql/https://user@host/",
            "/:graphiql/https://host:0/",
            "/:graphiql/https://host/a b",
            "/:graphiql/https://host/a\\b",
            "/:graphiql/https://host/?q=a b",
            "/:graphiql/https://host/?q=a\\b",
            "/:graphiql/https://host/#fragment",
            "/:graphiql/ftp://example.com/",
            "/:graphiql/graphqls://host/",
        ):
            with subtests.test(path=path), pytest.raises(ValueError):
                GraphQLRoute.parse(path)

    @pytest.mark.parametrize(
        ("destination", "expected"),
        [
            (
                "HTTP://[2001:0DB8::1]:443/a%2Fb?x=&x=%2f&",
                "http://[2001:db8::1]:443/a%2Fb?x=&x=%2f&",
            ),
            (
                "https://FA\u1e9e.example:443/a%2Fb?x=&x=%2f&",
                "https://xn--fa-hia.example/a%2Fb?x=&x=%2f&",
            ),
            (
                "fa\u00df.example:80/a%2Fb?x=&x=%2f&",
                "https://xn--fa-hia.example:80/a%2Fb?x=&x=%2f&",
            ),
        ],
    )
    def test_proxy_and_graphiql_share_destination_normalization(
        self, destination, expected
    ):
        route = GraphQLRoute.parse(GRAPHQL_PREFIX + destination)
        assert route is not None
        assert str(route.target) == expected
        assert route.target == parse_target("/" + destination)

    def test_graphql_navigation_uses_ordinary_routes_and_preserves_http_scheme(self):
        local = "http://127.0.0.1:8080"
        upstream = URL("https://example.com/dir/graphql")
        for explicit in (False, True):
            expected = (
                local + ("/https://" if explicit else "/") + "example.com/next?q=%2f"
            )
            assert (
                rewrite_url("../next?q=%2f", upstream, local, explicit_scheme=explicit)
                == expected
            )
            assert (
                rewrite_refresh(
                    '0; url="../next?q=%2f"', upstream, local, explicit_scheme=explicit
                )
                == "0; url=" + expected
            )
        assert (
            rewrite_url("http://example.com:80/a%2Fb?q=%2f", upstream, local)
            == local + "/http://example.com/a%2Fb?q=%2f"
        )
        assert (
            rewrite_refresh(
                "0; url=../next?q=%2f", URL("http://example.com/dir/graphql"), local
            )
            == "0; url=" + local + "/http://example.com/next?q=%2f"
        )

    def test_sharp_s_routes_and_navigation_do_not_target_ascii_ss_host(self, subtests):
        for host in ("fa\u00df.example", "xn--fa-hia.example", "fass.example"):
            expected_host = (
                "fass.example" if host == "fass.example" else "xn--fa-hia.example"
            )
            for prefix in ("", "https://"):
                with subtests.test(host=host, prefix=prefix):
                    target = parse_target(f"/{prefix}{host}:444/a%2Fb?q=%2f")
                    assert str(target) == f"https://{expected_host}:444/a%2Fb?q=%2f"
                    assert (
                        rewrite_url(
                            f"https://{host}/next?q=%2f",
                            target,
                            "http://127.0.0.1:8080",
                        )
                        == f"http://127.0.0.1:8080/{expected_host}/next?q=%2f"
                    )
                    assert (
                        rewrite_refresh(
                            f"0; url=https://{host}/next",
                            target,
                            "http://127.0.0.1:8080",
                        )
                        == f"0; url=http://127.0.0.1:8080/{expected_host}/next"
                    )

    def test_log_url_redacts_secrets_and_preserves_other_parameters(self):
        value = (
            "https://user:password@example.com/path?q=a%2Fb&q=two&empty="
            "&access_token=private&API%5FKEY=private&sig=private&code=private"
        )
        sanitized = log_url(value)
        assert (
            sanitized
            == "https://REDACTED@example.com/path?q=a%2Fb&q=two&empty=&access_token=REDACTED&API%5FKEY=REDACTED&sig=REDACTED&code=REDACTED"
        )
        assert "password" not in sanitized
        assert "private" not in sanitized
        assert "\n" not in log_url("https://example.com/\x01\n")

    def test_raw_route(self, subtests):
        url = parse_target("/FOO.azure.net.:443/a%2Fb?q=a%2Fb&q=two&empty=&plus=+")
        assert str(url) == "https://foo.azure.net/a%2Fb?q=a%2Fb&q=two&empty=&plus=+"
        for path in (
            "/",
            "//host/path",
            "/user@host/path",
            "/host:0/path",
            "/host/path#fragment",
        ):
            with subtests.test(path=path), pytest.raises(ValueError):
                parse_target(path)

    def test_navigation_headers(self, subtests):
        upstream = URL("https://foo.azure.net/dir/page?old=1", encoded=True)
        local = "http://localhost:8080"
        cases = {
            "/next": local + "/foo.azure.net/next",
            "../next": local + "/foo.azure.net/next",
            "//bar.azure.net:444/path?x=1#fragment": local
            + "/bar.azure.net:444/path?x=1#fragment",
            "?q=a%2Fb&q=2": local + "/foo.azure.net/dir/page?q=a%2Fb&q=2",
            "#fragment": local + "/foo.azure.net/dir/page?old=1#fragment",
            "https://bar.azure.net": local + "/bar.azure.net/",
            "http://foo.azure.net/": local + "/http://foo.azure.net/",
        }
        for value, expected in cases.items():
            with subtests.test(value=value):
                assert rewrite_url(value, upstream, local) == expected
        assert (
            rewrite_refresh('0; URL="../next"', upstream, local)
            == "0; url=" + cases["../next"]
        )
        assert rewrite_refresh("2", upstream, local) == "2"
        for value in (
            "ftp://foo.azure.net/",
            "javascript:alert(1)",
            "https://user@host/",
            "https://a\\b/",
        ):
            with pytest.raises(ValueError):
                rewrite_url(value, upstream, local)
        for value in ("oops", "0; url='unfinished"):
            with pytest.raises(ValueError):
                rewrite_refresh(value, upstream, local)

    def test_header_filtering(self):
        headers = CIMultiDict(
            [
                ("Connection", "X-Private"),
                ("X-Private", "secret"),
                ("Authorization", "caller-token"),
                ("Cookie", "session=one"),
                ("Set-Cookie", "session=two"),
                ("Host", "caller"),
                ("X-Repeat", "one"),
                ("X-Repeat", "two"),
                ("Transfer-Encoding", "chunked"),
            ]
        )
        outgoing = filtered_headers(headers, request=True)
        assert list(outgoing.items()) == [("X-Repeat", "one"), ("X-Repeat", "two")]


class TestProxy:
    @pytest.fixture(autouse=True)
    async def proxy_server(self, tls_contexts):
        self.server_tls, self.client_tls = tls_contexts
        self.requests = []
        self.stream_started = asyncio.Event()
        self.stream_release = asyncio.Event()
        app = web.Application(handler_args={"auto_decompress": False})
        app.router.add_route("*", "/{path:.*}", self.upstream)
        self.upstream_server = TestServer(app, host="127.0.0.1", scheme="https")
        await self.upstream_server.start_server(ssl=self.server_tls)
        self.acquire = AsyncMock(
            return_value=json.dumps(
                {
                    "accessToken": "proxy-token",
                    "expires_on": 4102444800,
                }
            )
        )
        self.tokens = TokenProvider(self.acquire)
        self.proxy = Proxy(
            self.tokens,
            port=0,
            tls=self.client_tls,
            authentication=ProxyAuthentication(None),
            config=Config((TokenRule("localhost"), TokenRule("127.0.0.1"))),
        )
        self.client = TestClient(TestServer(self.proxy.app, host="127.0.0.1"))
        await self.client.start_server()
        assert self.client.server.port is not None
        self.proxy.port = self.client.server.port

        try:
            yield
        finally:
            self.stream_release.set()
            await self.client.close()
            await self.upstream_server.close()

    def route(self, path="/echo", *, host="localhost"):
        return f"/{host}:{self.upstream_server.port}{path}"

    @pytest.mark.parametrize(
        ("method", "editor"),
        [
            ("OPTIONS", False),
            ("GET", True),
        ],
    )
    async def test_invalid_routes_are_rejected_before_preflight_or_editor_redirect(
        self, method, editor
    ):
        headers = (
            {"Host": f"localhost:{self.proxy.port}"}
            if editor
            else {
                "Origin": f"http://localhost:{self.proxy.port}",
                "Access-Control-Request-Method": "GET",
            }
        )
        response = await self.client.request(method, "/https://", headers=headers)
        assert response.status == 400
        assert await response.text() == "Invalid destination route\n"
        assert not self.requests
        self.acquire.assert_not_awaited()

    @pytest.mark.parametrize(
        ("path", "status"),
        [
            ("/%3Agraphiql/https://example.test/graphql", 400),
            ("/:%67raphiql/https://example.test/graphql", 400),
            ("/:graphiql%2Fhttps://example.test/graphql", 404),
            ("/%3Aunknown/https://example.test/graphql", 404),
            ("/:graphql/https://example.test/graphql", 404),
        ],
    )
    async def test_encoded_special_prefixes_never_become_forwarding(self, path, status):
        async with self.client.get(URL(path, encoded=True)) as response:
            assert response.status == status
            await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_dispatch_separates_local_pages_from_reverse_proxy_requests(self):
        destination = "https:/" + self.route("/a%2Fb?q=%2f&empty=")
        with patch.object(
            self.proxy.app[REVERSE_PROXY_KEY],
            "forward",
            new=AsyncMock(
                side_effect=lambda *args, **kwargs: web.Response(text="forwarded")
            ),
        ) as forward:
            for prefix in ("/", GRAPHQL_PREFIX):
                async with self.client.post(
                    URL(prefix + destination, encoded=True)
                ) as response:
                    assert response.status == 200
                    assert await response.text() == "forwarded"
            assert forward.await_count == 2
            for path in ("/", GRAPHQL_PREFIX + destination):
                async with self.client.get(URL(path, encoded=True)) as response:
                    assert response.status == 200
                    assert response.content_type == "text/html"
            assert forward.await_count == 2
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_authenticated_https_query_keeps_azure_auth_and_removes_proxy_key(
        self,
        subtests,
    ):
        self.proxy.authentication = ProxyAuthentication("local-key")
        route = "/https:/" + self.route(
            "/a%2Fb?x=%2f&azure-dev-proxy-token=local-key&empty="
        )
        for method in ("GET", "HEAD", "POST"):
            with subtests.test(method=method):
                response = await self.client.request(
                    method,
                    URL(route, encoded=True),
                    data=b"body",
                    allow_redirects=False,
                )
                assert response.status == 200
                assert "Location" not in response.headers
                assert await response.read() == (b"" if method == "HEAD" else b"body")
                seen = self.requests[-1]
                assert seen["path"] == "/a%2Fb?x=%2f&empty="
                assert seen["headers"]["Authorization"].startswith("Bearer ")
                assert "Cookie" not in seen["headers"]
        assert self.acquire.await_count == 1

    async def test_graphiql_pages_do_not_contact_upstream_or_acquire_tokens(self):
        path = GRAPHQL_PREFIX + "https:/" + self.route("/a%2Fb?q=%3Cscript%3E&empty=")
        for method in ("GET", "HEAD"):
            response = await self.client.request(method, URL(path, encoded=True))
            assert response.status == 200
            assert response.headers["Content-Type"] == "text/html; charset=utf-8"
            assert response.headers["Cache-Control"] == "no-store"
            assert response.headers["Referrer-Policy"] == "no-referrer"
            page = await response.text()
            if method == "GET":
                assert 'url: "' + path[len(GRAPHQL_PREFIX) :] + '"' in page
                assert "fetch: (url, options) => fetch(`/${url}`, options)" in page
                assert "__NONCE__" not in page
                assert "__TRANSPORT_URL__" not in page
                assert (
                    "frame-ancestors 'none'"
                    in response.headers["Content-Security-Policy"]
                )
                assert "azure-dev-proxy-csrf" not in page
            else:
                assert page == ""
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_schemeless_graphql_pages_and_posts_default_to_https(self):
        target = self.route("/a%2Fb?q=%2f&empty=")[1:]
        path = URL(GRAPHQL_PREFIX + target, encoded=True)
        async with self.client.get(path) as response:
            assert response.status == 200
            assert 'url: "https://' + target + '"' in await response.text()
        assert not self.requests
        self.acquire.assert_not_awaited()
        async with self.client.post(path, data=b"query") as response:
            assert response.status == 200
            assert await response.read() == b"query"
        assert self.requests[-1]["path"] == "/a%2Fb?q=%2f&empty="
        assert self.requests[-1]["headers"]["Authorization"] == "Bearer proxy-token"
        self.acquire.assert_awaited_once()

    async def test_graphql_https_posts_use_tokens_and_preserve_queries(self, subtests):
        path = "/a%2Fb?q=a%0Ab&empty=&escaped=%2f"
        body = b'{"query":"{ __typename }"}'
        for prefix in (GRAPHQL_PREFIX, "/"):
            with subtests.test(prefix=prefix):
                response = await self.client.post(
                    URL(prefix + "https:/" + self.route(path), encoded=True),
                    data=body,
                    headers={"Authorization": "caller-secret", "Cookie": "private=one"},
                )
                assert response.status == 200
                assert await response.read() == body
                seen = self.requests[-1]
                assert seen["path"] == path
                assert seen["headers"]["Authorization"] == "Bearer proxy-token"
                assert "Cookie" not in seen["headers"]
        assert self.acquire.await_count == 1

    async def test_graphql_posts_rewrite_navigation_to_ordinary_proxy_routes(self):
        destination = f"https://127.0.0.1:{self.upstream_server.port}"
        for endpoint, header, expected in (
            ("/redirect", "Location", "/echo?q=a%2Fb"),
            ("/refresh", "Refresh", "/echo#fragment"),
        ):
            async with self.client.post(
                GRAPHQL_PREFIX + destination + endpoint,
                allow_redirects=False,
            ) as response:
                assert (
                    response.headers[header]
                    == ("0; url=" if header == "Refresh" else "")
                    + self.proxy.local_origin
                    + "/"
                    + destination
                    + expected
                )
        response = await self.client.post(
            URL(GRAPHQL_PREFIX + destination + "/redirect", encoded=True),
            data=b"query",
        )
        assert response.status == 200
        assert response.content_type != "text/html"
        await response.read()
        assert self.requests[-1]["method"] == "GET"
        assert self.requests[-1]["headers"]["Authorization"].startswith("Bearer ")

    async def test_http_forwarding_is_anonymous_for_matching_base_and_temporary_rules(
        self,
        subtests,
    ):
        self.proxy.authentication = ProxyAuthentication("local-key")
        self.proxy.app[MANAGEMENT_KEY]._overrides["127.0.0.1"] = TokenRule(
            "127.0.0.1",
            "https://override.example",
        )
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.upstream)
        async with TestServer(app, host="127.0.0.1") as server:
            target = f"http://127.0.0.1:{server.port}/a%2Fb?q=%2f&empty="
            response = await self.client.get(
                URL(GRAPHQL_PREFIX + target, encoded=True),
                headers={"X-Azure-Dev-Proxy-Token": "local-key"},
            )
            assert response.status == 200
            assert 'url: "' + target + '"' in await response.text()
            assert not self.requests
            for prefix in ("/", GRAPHQL_PREFIX):
                for method in ("GET", "HEAD", "POST"):
                    if prefix == GRAPHQL_PREFIX and method != "POST":
                        continue
                    with subtests.test(prefix=prefix, method=method):
                        response = await self.client.request(
                            method,
                            URL(
                                prefix + target + "&azure-dev-proxy-token=local-key",
                                encoded=True,
                            ),
                            data=b"query",
                            headers={
                                "Authorization": "Bearer caller-secret",
                                "Proxy-Authorization": "proxy-secret",
                                "Cookie": "private=one",
                                "X-Azure-Dev-Proxy-Token": "local-key",
                            },
                        )
                        assert response.status == 200
                        await response.read()
                        seen = self.requests[-1]
                        assert seen["path"] == "/a%2Fb?q=%2f&empty="
                        for header in (
                            "Authorization",
                            "Proxy-Authorization",
                            "Cookie",
                            "X-Azure-Dev-Proxy-Token",
                        ):
                            assert header not in seen["headers"]
        self.acquire.assert_not_awaited()

    async def test_https_to_http_redirect_does_not_forward_azure_or_caller_credentials(
        self,
    ):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.upstream)
        async with TestServer(app, host="127.0.0.1") as server:
            destination = f"http://127.0.0.1:{server.port}/echo?q=%2f&empty="
            async with ClientSession(requote_redirect_url=False) as client:
                async with client.get(
                    self.proxy.local_origin + self.route("/redirect-to"),
                    params={"url": destination},
                    headers={
                        "Authorization": "Bearer caller-secret",
                        "Cookie": "private=one",
                    },
                ) as response:
                    assert response.status == 200
                    await response.read()
            assert self.requests[0]["headers"]["Authorization"].startswith("Bearer ")
            assert self.requests[-1]["path"] == "/echo?q=%2f&empty="
            assert "Authorization" not in self.requests[-1]["headers"]
            assert "Cookie" not in self.requests[-1]["headers"]
            assert self.acquire.await_count == 1
            self.requests.clear()
            async with ClientSession(requote_redirect_url=False) as client:
                async with client.get(
                    f"{self.proxy.local_origin}/http://127.0.0.1:{server.port}/redirect-to",
                    params={
                        "url": f"https://localhost:{self.upstream_server.port}/echo"
                    },
                ) as response:
                    assert response.status == 200
                    await response.read()
            assert "Authorization" not in self.requests[0]["headers"]
            assert self.requests[-1]["headers"]["Authorization"].startswith("Bearer ")
            assert self.acquire.await_count == 1

    async def test_graphql_routes_enforce_browser_trust_and_localhost_redirects(self):
        path = "https:/" + self.route()
        for prefix in (GRAPHQL_PREFIX, "/"):
            route = prefix + path
            response = await self.client.post(
                route, headers={"Origin": "https://evil.example"}
            )
            assert response.status == 403
            await response.read()
            response = await self.client.get(
                route,
                headers={"Host": f"localhost:{self.proxy.port}"},
                allow_redirects=False,
            )
            assert response.status == 307
            assert response.headers["Location"] == self.proxy.local_origin + route
            await response.read()
            response = await self.client.options(
                route,
                headers={
                    "Origin": self.proxy.local_origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
            )
            assert response.status == 204
            assert (
                response.headers["Access-Control-Allow-Origin"]
                == self.proxy.local_origin
            )
            await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_graphql_invalid_routes_methods_and_self_loops_are_rejected(
        self, subtests
    ):
        for path, method, status in (
            (GRAPHQL_PREFIX + "https:/" + self.route(), "PUT", 405),
            (GRAPHQL_PREFIX + "ftp://example.com/", "GET", 400),
            ("/ftp://example.com/", "POST", 400),
            (f"{GRAPHQL_PREFIX}http://127.0.0.1:{self.proxy.port}/graphql", "GET", 400),
            (
                f"{GRAPHQL_PREFIX}https://localhost:{self.proxy.port}/graphql",
                "POST",
                400,
            ),
            ("/graphqls://example.com/graphql", "GET", 400),
            ("/_graphql/transport/graphql://example.com/graphql", "POST", 400),
            ("/_azure-dev-proxy/config", "GET", 400),
        ):
            with subtests.test(path=path, method=method):
                response = await self.client.request(method, path)
                assert response.status == status
                await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def upstream(self, request):
        if request.path == "/upload":
            first = await request.content.readexactly(5)
            self.stream_started.set()
            body = first + await request.read()
        else:
            body = await request.read()
        self.requests.append(
            {
                "method": request.method,
                "path": request.raw_path,
                "headers": request.headers.copy(),
                "body": body,
            }
        )
        if request.path == "/redirect-to":
            return web.Response(status=302, headers={"Location": request.query["url"]})
        if request.path == "/redirect":
            return web.Response(
                status=302,
                headers={
                    "Location": f"https://127.0.0.1:{self.upstream_server.port}/echo?q=a%2Fb",
                },
            )
        if request.path == "/refresh":
            return web.Response(headers={"Refresh": '0; url="/echo#fragment"'})
        if request.path == "/http":
            return web.Response(status=302, headers={"Location": "http://example.com/"})
        if request.path == "/malformed":
            return web.Response(headers={"Refresh": "nonsense"})
        if request.path == "/compressed":
            return web.Response(
                body=gzip.compress(b"binary\x00data" * 100),
                headers={
                    "Content-Encoding": "gzip",
                    "Content-Type": "application/octet-stream",
                },
            )
        if request.path == "/duplicates":
            return web.Response(
                body=b"ok",
                headers=CIMultiDict(
                    [
                        ("X-Repeat", "one"),
                        ("X-Repeat", "two"),
                        ("Set-Cookie", "private=value"),
                        ("Connection", "X-Private"),
                        ("X-Private", "secret"),
                    ]
                ),
            )
        if request.path == "/exposed":
            return web.Response(
                body=b"page",
                headers=CIMultiDict(
                    [
                        ("Access-Control-Expose-Headers", "X-Continuation, location"),
                        (
                            "Access-Control-Expose-Headers",
                            "X-Request-ID, x-continuation, *",
                        ),
                        ("X-Continuation", "next-page"),
                        ("X-Request-ID", "request-one"),
                    ]
                ),
            )
        if request.path == "/empty":
            return web.Response(status=204)
        if request.path == "/error":
            return web.Response(status=403, text="denied")
        if request.path == "/slow":
            await asyncio.sleep(0.1)
            return web.Response(text="late")
        if request.path == "/stream":
            response = web.StreamResponse()
            await response.prepare(request)
            await response.write(b"first")
            self.stream_started.set()
            await self.stream_release.wait()
            try:
                await response.write(b"second")
                await response.write_eof()
            except ConnectionResetError:
                pass
            return response
        return web.Response(body=body if body else b"ok")

    async def test_methods_raw_query_body_and_auth(self, subtests):
        path = "/a%2Fb?q=a%2Fb&q=two&empty=&plus=+&line=a%0Ab&other=%0a"
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with subtests.test(method=method):
                body = b"x" * 200000 if method in ("POST", "PUT", "PATCH") else None
                response = await self.client.request(
                    method,
                    URL(self.route(path), encoded=True),
                    data=body,
                    headers={"Authorization": "caller-secret", "Cookie": "private=one"},
                )
                assert response.status == 200
                expected = b"" if method == "HEAD" else body or b"ok"
                assert await response.read() == expected
                seen = self.requests[-1]
                assert seen["path"] == path
                assert seen["method"] == method
                assert seen["body"] == (body or b"")
                assert seen["headers"]["Authorization"] == "Bearer proxy-token"
                assert "Cookie" not in seen["headers"]
                assert (
                    seen["headers"]["Host"] == f"localhost:{self.upstream_server.port}"
                )
        assert self.acquire.await_count == 1
        self.acquire.assert_awaited_with(
            f"https://localhost:{self.upstream_server.port}"
        )

    async def test_unmatched_and_failed_acquisition_are_anonymous(self, caplog):
        self.proxy.config = replace(self.proxy.config, token_rules=())
        response = await self.client.get(
            self.route(), headers={"Authorization": "caller-secret"}
        )
        assert response.status == 200
        await response.read()
        assert "Authorization" not in self.requests[-1]["headers"]
        self.acquire.assert_not_awaited()
        self.proxy.config = replace(
            self.proxy.config, token_rules=(TokenRule("localhost"),)
        )
        self.acquire.side_effect = AcquisitionError("no token rights")
        caplog.clear()
        with caplog.at_level("WARNING", logger="azure_dev_proxy.tokens"):
            response = await self.client.get(self.route("/error"))
        assert any(
            record.name == "azure_dev_proxy.tokens"
            or record.name.startswith("azure_dev_proxy.tokens" + ".")
            for record in caplog.records
        )
        assert response.status == 403
        assert await response.text() == "denied"
        assert "Authorization" not in self.requests[-1]["headers"]
        assert self.acquire.await_count == 1

    async def test_every_call_logs_url_and_token_source_once(self, caplog):
        path = "/echo?q=a%2Fb&access_token=private-query"
        for source in ("acquired", "cached"):
            caplog.clear()
            with caplog.at_level("INFO", logger="azure_dev_proxy.proxy"):
                response = await self.client.get(
                    URL(self.route(path), encoded=True),
                    headers={"Authorization": "private-header"},
                )
                await response.read()
            assert any(
                record.name == "azure_dev_proxy.proxy"
                or record.name.startswith("azure_dev_proxy.proxy" + ".")
                for record in caplog.records
            )
            calls = [line for line in caplog.messages if "Proxy call " in line]
            assert len(calls) == 1
            assert (
                calls[0]
                == f"Proxy call url=https://localhost:{self.upstream_server.port}/echo?q=a%2Fb&access_token=REDACTED method=GET token=yes source={source}"
            )
            assert "private" not in calls[0]
            assert "proxy-token" not in calls[0]
        self.proxy.config = replace(self.proxy.config, token_rules=())
        caplog.clear()
        with caplog.at_level("INFO", logger="azure_dev_proxy.proxy"):
            response = await self.client.get(self.route())
            await response.read()
        assert any(
            record.name == "azure_dev_proxy.proxy"
            or record.name.startswith("azure_dev_proxy.proxy" + ".")
            for record in caplog.records
        )
        assert "token=no source=not-allowlisted" in caplog.messages[0]

    async def test_failed_and_rejected_calls_are_logged(self, caplog):
        self.acquire.side_effect = AcquisitionError("no token rights")
        for source in ("unavailable", "cooldown"):
            caplog.clear()
            with caplog.at_level("INFO", logger="azure_dev_proxy"):
                response = await self.client.get(self.route("/error"))
                await response.read()
            assert any(
                record.name == "azure_dev_proxy"
                or record.name.startswith("azure_dev_proxy" + ".")
                for record in caplog.records
            )
            calls = [line for line in caplog.messages if "Proxy call " in line]
            assert len(calls) == 1
            assert f"token=no source={source}" in calls[0]
            assert response.status == 403
        caplog.clear()
        with caplog.at_level("INFO", logger="azure_dev_proxy.proxy"):
            response = await self.client.get(
                self.route(), headers={"Host": "invalid.example"}
            )
            await response.read()
        assert any(
            record.name == "azure_dev_proxy.proxy"
            or record.name.startswith("azure_dev_proxy.proxy" + ".")
            for record in caplog.records
        )
        assert response.status == 400
        assert "token=no source=not-attempted" in caplog.messages[0]

    async def test_redirect_evaluates_second_domain_and_shared_resource_independently(
        self,
    ):
        self.proxy.config = replace(
            self.proxy.config,
            token_rules=(
                TokenRule("localhost", "https://foo.example"),
                TokenRule("127.0.0.1", "https://foo.example"),
            ),
        )
        self.acquire.side_effect = [
            json.dumps({"accessToken": "token-one", "expires_on": 4102444800}),
            json.dumps({"accessToken": "token-two", "expires_on": 4102444800}),
        ]
        response = await self.client.get(self.route("/redirect"), allow_redirects=False)
        assert response.status == 302
        assert len(self.requests) == 1
        expected = self.proxy.local_origin + self.route(
            "/echo?q=a%2Fb", host="127.0.0.1"
        )
        assert response.headers["Location"] == expected
        await response.read()
        next_route = expected[len(self.proxy.local_origin) :]
        response = await self.client.get(URL(next_route, encoded=True))
        assert response.status == 200
        await response.read()
        assert self.requests[0]["headers"]["Authorization"] == "Bearer token-one"
        assert self.requests[1]["headers"]["Authorization"] == "Bearer token-two"
        assert self.acquire.await_count == 2

    async def test_refresh_and_unsupported_navigation(self, caplog):
        response = await self.client.get(self.route("/refresh"))
        assert response.headers[
            "Refresh"
        ] == "0; url=" + self.proxy.local_origin + self.route("/echo#fragment")
        await response.read()
        response = await self.client.get(self.route("/http"), allow_redirects=False)
        assert response.status == 302
        assert (
            response.headers["Location"]
            == self.proxy.local_origin + "/http://example.com/"
        )
        await response.read()
        caplog.clear()
        with caplog.at_level("WARNING", logger="azure_dev_proxy.proxy"):
            response = await self.client.get(
                self.route("/malformed"), allow_redirects=False
            )
        assert any(
            record.name == "azure_dev_proxy.proxy"
            or record.name.startswith("azure_dev_proxy.proxy" + ".")
            for record in caplog.records
        )
        assert response.status == 502
        assert "navigation" in await response.text()

    async def test_compressed_duplicate_headers_and_empty_response(self):
        response = await self.client.get(
            self.route("/compressed"), auto_decompress=False
        )
        assert response.headers["Content-Encoding"] == "gzip"
        assert gzip.decompress(await response.read()) == b"binary\x00data" * 100
        response = await self.client.get(self.route("/duplicates"))
        assert response.headers.getall("X-Repeat") == ["one", "two"]
        assert "Set-Cookie" not in response.headers
        assert "X-Private" not in response.headers
        await response.read()
        response = await self.client.get(self.route("/empty"))
        assert response.status == 204
        assert await response.read() == b""

    async def test_compressed_uploads_preserve_encoded_bytes_and_framing(
        self, subtests
    ):
        data = b"binary\x00upload" * 1000
        for encoding, encode in (("gzip", gzip.compress), ("deflate", zlib.compress)):
            body = encode(data)
            for method in ("POST", "PUT", "PATCH"):
                for chunked in (False, True):

                    async def chunks():
                        yield body[:5]
                        yield body[5:]

                    with subtests.test(
                        encoding=encoding, method=method, chunked=chunked
                    ):
                        response = await self.client.request(
                            method,
                            self.route(),
                            data=chunks() if chunked else body,
                            headers={"Content-Encoding": encoding},
                        )
                        assert response.status == 200
                        assert await response.read() == body
                        seen = self.requests[-1]
                        assert seen["body"] == body
                        assert seen["headers"]["Content-Encoding"] == encoding
                        if chunked:
                            assert "Content-Length" not in seen["headers"]
                            assert seen["headers"]["Transfer-Encoding"] == "chunked"
                        else:
                            assert seen["headers"]["Content-Length"] == str(len(body))

    async def test_streaming_and_downstream_cancellation(self):
        response = await self.client.get(self.route("/stream"))
        await self.stream_started.wait()
        assert await response.content.readexactly(5) == b"first"
        assert not self.stream_release.is_set()
        self.stream_release.set()
        assert await response.content.read() == b"second"
        self.stream_release.clear()
        response = await self.client.get(self.route("/stream"))
        assert await response.content.readexactly(5) == b"first"
        response.close()
        self.stream_release.set()
        await asyncio.sleep(0.01)
        response = await self.client.get(self.route())
        assert response.status == 200
        await response.read()

    async def test_streaming_upload_is_not_buffered(self):
        async def chunks():
            yield b"first"
            await asyncio.wait_for(self.stream_started.wait(), 2)
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(self.proxy.activity.wait_for_idle(0.02), 0.05)
            yield b"second"

        response = await self.client.post(self.route("/upload"), data=chunks())
        assert response.status == 200
        assert await response.read() == b"firstsecond"
        assert self.requests[-1]["body"] == b"firstsecond"

    async def test_parser_errors_do_not_log_request_credentials(self, caplog):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy.port)
        try:
            caplog.clear()
            with caplog.at_level("ERROR", logger="azure_dev_proxy.http"):
                writer.write(
                    f"GET /bad?private-query HTTP/1.1\r\nHost: localhost:{self.proxy.port}\r\nBad Header: private-token\r\nAuthorization: private-token\r\n\r\n".encode()
                )
                await writer.drain()
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            assert any(
                record.name == "azure_dev_proxy.http"
                or record.name.startswith("azure_dev_proxy.http" + ".")
                for record in caplog.records
            )
            assert response.startswith(b"HTTP/1.0 400")
            assert "private" not in caplog.text
            assert "HTTP server failure (" in caplog.text
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_local_safeguards(self):
        for headers, expected in (
            ({"Host": "evil.example"}, 400),
            ({"Upgrade": "websocket"}, 400),
        ):
            response = await self.client.get(self.route(), headers=headers)
            assert response.status == expected
            await response.read()
        response = await self.client.get(f"/localhost:{self.proxy.port}/echo")
        assert response.status == 400
        await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_explicitly_trusted_browser_calls_are_allowed_and_authenticated(
        self, subtests
    ):
        self.proxy.config = replace(
            self.proxy.config, trusted_origins=("http://localhost:3000",)
        )
        headers = {
            "Origin": "http://localhost:3000",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-User": "?1",
        }
        response = await self.client.get(self.route(), headers=headers)
        assert response.status == 200
        await response.read()
        assert self.requests[-1]["headers"]["Authorization"] == "Bearer proxy-token"
        assert self.acquire.await_count == 1
        for method, changes in (
            ("POST", {}),
            ("GET", {"Sec-Fetch-User": ""}),
            ("GET", {"Sec-Fetch-Dest": "iframe"}),
            ("GET", {"Sec-Fetch-Mode": "cors"}),
            ("GET", {"Origin": "http://localhost:3000"}),
        ):
            with subtests.test(method=method, changes=changes):
                response = await self.client.request(
                    method, self.route(), headers=headers | changes
                )
                assert response.status == 200
                await response.read()
                assert (
                    self.requests[-1]["headers"]["Authorization"]
                    == "Bearer proxy-token"
                )
        assert len(self.requests) == 6
        assert self.acquire.await_count == 1

    async def test_cors_preflight_is_local_and_actual_request_gets_token(self, caplog):
        origin = "http://localhost:3000"
        self.proxy.config = replace(self.proxy.config, trusted_origins=(origin,))
        caplog.clear()
        with caplog.at_level("INFO", logger="azure_dev_proxy.proxy"):
            response = await self.client.options(
                self.route(),
                headers={
                    "Origin": origin,
                    "Sec-Fetch-Site": "cross-site",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization, content-type, x-request-id",
                    "Access-Control-Request-Private-Network": "true",
                },
            )
            await response.read()
        assert any(
            record.name == "azure_dev_proxy.proxy"
            or record.name.startswith("azure_dev_proxy.proxy" + ".")
            for record in caplog.records
        )
        assert response.status == 204
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert response.headers["Access-Control-Allow-Credentials"] == "true"
        assert "POST" in response.headers["Access-Control-Allow-Methods"]
        assert (
            response.headers["Access-Control-Allow-Headers"]
            == "authorization, content-type, x-request-id"
        )
        assert response.headers["Access-Control-Allow-Private-Network"] == "true"
        assert len(caplog.messages) == 1
        assert "token=no source=cors-preflight" in caplog.messages[0]
        assert not self.requests
        self.acquire.assert_not_awaited()
        response = await self.client.post(
            self.route(),
            headers={
                "Origin": origin,
                "Sec-Fetch-Site": "cross-site",
                "X-Request-ID": "request-one",
            },
            json={"query": "{ __typename }"},
        )
        assert response.status == 200
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert response.headers["Access-Control-Allow-Credentials"] == "true"
        assert "Origin" in ", ".join(response.headers.getall("Vary"))
        await response.read()
        assert self.requests[-1]["headers"]["Authorization"] == "Bearer proxy-token"
        assert self.requests[-1]["headers"]["X-Request-ID"] == "request-one"
        assert self.acquire.await_count == 1

    async def test_cors_headers_apply_to_streams_and_errors(self):
        origin = "https://developer.example"
        self.proxy.config = replace(self.proxy.config, trusted_origins=(origin,))
        response = await self.client.get(
            self.route("/stream"), headers={"Origin": origin}
        )
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert await response.content.readexactly(5) == b"first"
        self.stream_release.set()
        assert await response.content.read() == b"second"
        for path, expected in ((self.route("/error"), 403), ("/invalid:0/", 400)):
            response = await self.client.get(path, headers={"Origin": origin})
            assert response.status == expected
            assert response.headers["Access-Control-Allow-Origin"] == origin
            await response.read()
        response = await self.client.get(
            self.route("/http"),
            headers={"Origin": origin},
            allow_redirects=False,
        )
        assert response.status == 302
        assert response.headers["Access-Control-Allow-Origin"] == origin
        await response.read()

    async def test_cors_exposure_preserves_upstream_headers_and_adds_navigation_headers(
        self,
    ):
        origin = "https://developer.example"
        self.proxy.config = replace(self.proxy.config, trusted_origins=(origin,))
        response = await self.client.get(
            self.route("/exposed"), headers={"Origin": origin}
        )
        assert response.status == 200
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert response.headers.getall("Access-Control-Expose-Headers") == [
            "X-Continuation, location, X-Request-ID, *, Refresh"
        ]
        assert response.headers["X-Continuation"] == "next-page"
        assert response.headers["X-Request-ID"] == "request-one"
        assert await response.read() == b"page"

    async def test_invalid_cors_preflights_are_explicit_errors(self):
        self.proxy.config = replace(
            self.proxy.config, trusted_origins=("https://developer.example",)
        )
        for changes, expected in (
            ({"Access-Control-Request-Method": "CONNECT"}, 405),
            ({"Access-Control-Request-Headers": "Bad Header"}, 400),
        ):
            response = await self.client.options(
                self.route(),
                headers={
                    "Origin": "https://developer.example",
                    "Access-Control-Request-Method": "POST",
                }
                | changes,
            )
            assert response.status == expected
            assert (
                response.headers["Access-Control-Allow-Origin"]
                == "https://developer.example"
            )
            await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_untrusted_browser_calls_are_rejected_before_tokens_or_forwarding(
        self,
        subtests,
    ):
        self.proxy.config = replace(
            self.proxy.config, trusted_origins=("https://developer.example",)
        )
        navigation = {
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-User": "?1",
        }
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            for headers in (
                navigation,
                navigation | {"Sec-Fetch-Dest": "iframe"},
                {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"},
                {"Sec-Fetch-Site": "same-site"},
                {"Sec-Fetch-Mode": "cors"},
                {"Sec-Fetch-Site": "none"},
                {"Origin": "https://attacker.example"},
                {"Origin": "null"},
                {"Origin": "http://localhost:3000"},
                {"Origin": "https://developer.example:444"},
                {"Origin": "http://developer.example"},
                {"Origin": "https://developer.example.attacker.example"},
                {"Origin": "https://sub.developer.example"},
                {"Origin": "https://developer.example/"},
                {
                    "Origin": "https://attacker.example",
                    "Referer": self.proxy.local_origin + "/",
                },
                {"Referer": "https://attacker.example/"},
                {
                    "Origin": "https://attacker.example",
                    "Access-Control-Request-Method": "POST",
                },
            ):
                with subtests.test(method=method, headers=headers):
                    response = await self.client.request(
                        method, self.route(), headers=headers
                    )
                    assert response.status == 403
                    assert "Access-Control-Allow-Origin" not in response.headers
                    assert (
                        "Access-Control-Allow-Private-Network" not in response.headers
                    )
                    await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()

    async def test_trusted_navigation_and_same_origin_requests_without_origin_are_allowed(
        self,
        subtests,
    ):
        self.proxy.config = replace(
            self.proxy.config, trusted_origins=("https://developer.example",)
        )
        for headers in (
            {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"},
            {
                "Sec-Fetch-Site": "cross-site",
                "Referer": f"http://localhost:{self.proxy.port}/",
            },
            {
                "Sec-Fetch-Site": "cross-site",
                "Referer": "https://developer.example/path",
            },
            {
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-User": "?1",
            },
        ):
            with subtests.test(headers=headers):
                response = await self.client.get(self.route(), headers=headers)
                assert response.status == 200
                await response.read()
        assert len(self.requests) == 4
        assert self.acquire.await_count == 1

    async def test_trusting_sharp_s_origin_never_authorizes_ascii_ss_origin(
        self, subtests
    ):
        config = Config.parse(
            {
                "token_rules": [],
                "trusted_origins": ["https://fa\u00df.example"],
            }
        )
        self.proxy.config = replace(
            self.proxy.config, trusted_origins=config.trusted_origins
        )
        assert self.proxy.is_trusted_origin("https://fa\xdf.example")
        assert self.proxy.is_trusted_origin("https://xn--fa-hia.example")
        assert not self.proxy.is_trusted_origin("https://fass.example")
        for method, headers in (
            ("POST", {"Origin": "https://fass.example"}),
            (
                "GET",
                {
                    "Referer": "https://fass.example/page",
                    "Sec-Fetch-Site": "cross-site",
                },
            ),
            (
                "OPTIONS",
                {
                    "Origin": "https://fass.example",
                    "Access-Control-Request-Method": "POST",
                },
            ),
        ):
            with subtests.test(method=method):
                response = await self.client.request(
                    method, self.route(), headers=headers
                )
                assert response.status == 403
                assert "Access-Control-Allow-Origin" not in response.headers
                await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()
        origin = "https://xn--fa-hia.example"
        response = await self.client.options(
            self.route(),
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status == 204
        assert response.headers["Access-Control-Allow-Origin"] == origin
        await response.read()
        assert not self.requests
        self.acquire.assert_not_awaited()
        response = await self.client.post(
            self.route(), headers={"Origin": origin}, data=b"allowed"
        )
        assert response.status == 200
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert await response.read() == b"allowed"
        response = await self.client.get(
            self.route(),
            headers={
                "Referer": origin + "/page",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        assert response.status == 200
        await response.read()
        assert len(self.requests) == 2
        assert self.acquire.await_count == 1

    async def test_same_origin_browser_graphql_calls_are_allowed(self):
        response = await self.client.post(
            self.route(),
            headers={
                "Origin": f"http://127.0.0.1:{self.proxy.port}",
                "Sec-Fetch-Site": "same-origin",
            },
            json={"query": "{ __typename }"},
        )
        assert response.status == 200
        await response.read()
        assert self.acquire.await_count == 1

    async def test_connect_rejected(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy.port)
        try:
            writer.write(
                f"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:{self.proxy.port}\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
            response = await reader.read()
            assert response.startswith(b"HTTP/1.1 405"), response
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_timeout_and_tls_verification(self, caplog):
        await self.client.close()
        self.tokens = TokenProvider(self.acquire)
        self.proxy = Proxy(
            self.tokens,
            port=0,
            tls=self.client_tls,
            read_timeout=0.01,
            authentication=ProxyAuthentication(None),
            config=Config((TokenRule("localhost"),)),
        )
        self.client = TestClient(TestServer(self.proxy.app, host="127.0.0.1"))
        await self.client.start_server()
        assert self.client.server.port is not None
        self.proxy.port = self.client.server.port
        caplog.clear()
        with caplog.at_level("WARNING", logger="azure_dev_proxy.proxy"):
            response = await self.client.get(self.route("/slow"))
        assert any(
            record.name == "azure_dev_proxy.proxy"
            or record.name.startswith("azure_dev_proxy.proxy" + ".")
            for record in caplog.records
        )
        assert response.status == 504
        await response.read()
        self.proxy.tls = True
        caplog.clear()
        with caplog.at_level("WARNING"):
            response = await self.client.get(self.route())
            await asyncio.sleep(0.01)
        assert any(
            record.name == "azure_dev_proxy.proxy"
            or record.name.startswith("azure_dev_proxy.proxy" + ".")
            for record in caplog.records
        )
        assert any(
            record.name == "asyncio" or record.name.startswith("asyncio" + ".")
            for record in caplog.records
        )
        assert response.status == 502
        await response.read()

    @pytest.mark.skipif(os.name == "nt", reason="Native POSIX fake CLI fixture")
    async def test_real_azure_cli_adapter_with_https_listener(self, tmp_path):
        executable = tmp_path / "fake az"
        shutil.copyfile(Path(__file__).with_name("fake_az.py"), executable)
        executable.chmod(0o755)
        self.tokens.acquire = AzureCLI(str(executable)).acquire
        response = await self.client.get(self.route())
        assert response.status == 200
        await response.read()
        assert self.requests[-1]["headers"]["Authorization"] == "Bearer fake-localhost"

    async def test_explicit_routes_and_overrides_reach_https_upstream(self):
        port = self.client.server.port
        response = await self.client.get(
            "/https:/" + self.route("/redirect"),
            allow_redirects=False,
        )
        assert response.status == 302
        assert (
            response.headers["Location"]
            == f"http://127.0.0.1:{port}/https://127.0.0.1:{self.upstream_server.port}/echo?q=a%2Fb"
        )
        await response.read()
        response = await self.client.get("/", headers={"Host": f"localhost:{port}"})
        page = await response.text()
        csrf = page.split('name="azure-dev-proxy-csrf" content="')[1].split('"')[0]
        response = await self.client.post(
            "/:config",
            json={"host": "localhost", "resource": "https://override.example"},
            headers={
                "Host": f"localhost:{port}",
                "Origin": f"http://localhost:{port}",
                "X-Azure-Proxy-CSRF": csrf,
            },
        )
        assert response.status == 200
        await response.read()
        response = await self.client.get(
            URL(
                "/https:/" + self.route("/a%2Fb?q=%2f&q=two&empty="),
                encoded=True,
            )
        )
        assert response.status == 200
        await response.read()
        assert self.requests[-1]["path"] == "/a%2Fb?q=%2f&q=two&empty="
        assert self.requests[-1]["headers"]["Authorization"].startswith("Bearer ")
        self.acquire.assert_awaited_with("https://override.example")

    async def test_stream_activity_prevents_idle_exit_until_body_completes(self):
        response = await self.client.get(self.route("/stream"))
        await asyncio.wait_for(self.stream_started.wait(), 1)
        idle = asyncio.create_task(self.proxy.activity.wait_for_idle(0.02))
        try:
            await asyncio.sleep(0.05)
            assert not idle.done()
            self.stream_release.set()
            assert await response.read() == b"firstsecond"
            await asyncio.wait_for(idle, 1)
        finally:
            idle.cancel()
            await asyncio.gather(idle, return_exceptions=True)


class TestForwardingFailures:
    @pytest.fixture
    def forwarding(self):
        proxy = Proxy(
            TokenProvider(AsyncMock()),
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        request = make_mocked_request(
            "GET",
            "/https://foo.example/",
            app=proxy.app,
        )
        request[ROUTE_KEY] = "/https://foo.example/"
        return proxy, request, proxy.app[REVERSE_PROXY_KEY]

    async def test_forwarding_requires_a_started_session(self, forwarding):
        proxy, request, router = forwarding
        with pytest.raises(RuntimeError, match="Proxy session has not started"):
            await router.forward(request, URL("https://foo.example/"), ProxyCall("foo"))
        assert proxy.session is None
        assert not proxy.tokens.pending

    async def test_upstream_protocol_upgrade_is_rejected(self, forwarding):
        proxy, request, router = forwarding
        upstream = MagicMock(status=101, headers=CIMultiDict())
        session = MagicMock()
        session.request.return_value.__aenter__.return_value = upstream
        proxy.session = session
        with pytest.raises(web.HTTPBadGateway) as error:
            await router.forward(request, URL("https://foo.example/"), ProxyCall("foo"))
        assert error.value.text == "Upstream protocol upgrades are not supported\n"
        upstream.content.iter_chunked.assert_not_called()
        session.request.return_value.__aexit__.assert_awaited_once()

    @pytest.mark.parametrize("connected", [True, False])
    async def test_stream_failure_after_headers_does_not_send_a_second_response(
        self, forwarding, connected, caplog
    ):
        proxy, request, router = forwarding
        transport = MagicMock() if connected else None
        request._protocol.transport = transport

        async def chunks(size):
            yield b"foo"
            raise OSError("private detail")

        upstream = MagicMock(status=200, headers=CIMultiDict())
        upstream.content.iter_chunked.side_effect = chunks
        session = MagicMock()
        session.request.return_value.__aenter__.return_value = upstream
        proxy.session = session
        response = MagicMock(
            prepared=True, prepare=AsyncMock(), write=AsyncMock(), write_eof=AsyncMock()
        )
        with patch(
            "azure_dev_proxy.routers.reverse_proxy.web.StreamResponse",
            return_value=response,
        ):
            result = await router.forward(
                request, URL("https://foo.example/"), ProxyCall("foo")
            )
        assert result is response
        response.prepare.assert_awaited_once_with(request)
        response.write.assert_awaited_once_with(b"foo")
        response.write_eof.assert_not_awaited()
        if transport is not None:
            transport.close.assert_called_once()
        assert "Upstream failure for https://foo.example (OSError)" in caplog.text
        assert "private detail" not in caplog.text
        session.request.return_value.__aexit__.assert_awaited_once()


class TestLauncher:
    async def test_real_cli_listener_and_shutdown(self, tmp_path):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "azure_dev_proxy",
            "--port",
            str(port),
            "--az-path",
            "/missing/az",
            "--config",
            str(tmp_path / "azure-dev-proxy/config.json"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            async with ClientSession(cookie_jar=CookieJar(unsafe=True)) as client:
                for _ in range(100):
                    if process.returncode is not None:
                        pytest.fail("Proxy CLI exited before accepting requests")
                    try:
                        async with client.get(f"http://127.0.0.1:{port}/") as response:
                            assert response.status == 401
                            break
                    except OSError:
                        await asyncio.sleep(0.02)
                else:
                    pytest.fail("Proxy CLI never became responsive")
                token = (tmp_path / "azure-dev-proxy/auth-token").read_text().strip()
                async with client.get(
                    f"http://127.0.0.1:{port}/",
                    params={"azure-dev-proxy-token": token},
                ) as response:
                    assert response.status == 200
                async with client.get(f"http://127.0.0.1:{port}/:config") as response:
                    assert response.status == 200
                    mappings = await response.json()
                    installed = Config.load(tmp_path / "azure-dev-proxy/config.json")
                    assert installed == Config.defaults()
                    assert mappings["base_rules"] == installed.as_dict()["token_rules"]
                    effective = Config(
                        tuple(
                            sorted(
                                installed.token_rules, key=lambda rule: rule.priority
                            )
                        )
                    )
                    assert (
                        mappings["effective_rules"]
                        == effective.as_dict()["token_rules"]
                    )
        finally:
            if process.returncode is None:
                process.terminate()
            output, errors = await asyncio.wait_for(process.communicate(), 5)
        assert process.returncode == 0
        assert b"Azure proxy listening at" in output
        assert b"INFO: Proxy call url=" in errors
        assert b" method=GET token=no source=not-attempted" in errors
        assert b"token=no source=not-attempted" in errors
        for host in ("localhost", "127.0.0.1"):
            assert (
                f"http://{host}:{port}/?azure-dev-proxy-token={token}".encode()
                in errors
            )
        request_logs = [line for line in errors.splitlines() if b"Proxy call " in line]
        assert all((token.encode() not in line for line in request_logs))
        assert b"Traceback" not in errors
