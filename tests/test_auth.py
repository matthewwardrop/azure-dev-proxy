from __future__ import annotations

import asyncio
import html
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlencode

import pytest
from aiohttp import CookieJar, web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from yarl import URL

from azure_dev_proxy.auth import (
    LOGIN_PATH,
    SESSION_PATH,
    TOKEN_HEADER,
    TOKEN_PARAMETER,
    ROUTE_KEY,
    ProxyAuthentication,
)
from azure_dev_proxy.config import Config, TokenRule
from azure_dev_proxy.proxy import Proxy
from azure_dev_proxy.tokens import TokenProvider


class TestKey:
    def test_existing_symlink_is_rejected(self, tmp_path):
        target = tmp_path / "foo"
        target.write_text("foo")
        path = tmp_path / "bar"
        path.symlink_to(target)
        with pytest.raises(ValueError, match="symbolic link"):
            ProxyAuthentication.load(path)

    def test_windows_key_loading_does_not_require_posix_permissions(self, tmp_path):
        path = tmp_path / "foo"
        path.write_text("foo\r\n")
        with patch("azure_dev_proxy.auth.os.name", "nt"):
            auth = ProxyAuthentication.load(path)
        assert auth.login_url("http://localhost:8080").endswith("=foo")

    def test_disabled_authentication_has_no_login_key_or_session_signature(self):
        auth = ProxyAuthentication(None)
        assert auth.login_url("http://localhost:8080") == "http://localhost:8080/"
        request = make_mocked_request("GET", "/", headers={"Host": "localhost:8080"})
        with pytest.raises(RuntimeError, match="Authentication is disabled"):
            auth._signature(request, "foo")

    def test_generated_key_is_private_stable_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth-token"
            with ThreadPoolExecutor(max_workers=4) as pool:
                authenticators = list(
                    pool.map(lambda _: ProxyAuthentication.load(path), range(8))
                )
            urls = [auth.login_url("http://localhost:8080") for auth in authenticators]
            assert all((url == urls[0] for url in urls))
            assert path.read_text().strip() in urls[0]
            if os.name != "nt":
                assert path.stat().st_mode & 511 == 384
                path.chmod(0o644)
                with pytest.raises(ValueError):
                    ProxyAuthentication.load(path)

    def test_explicit_and_disabled_modes_do_not_create_key_files(self, subtests):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth-token"
            auth = ProxyAuthentication.load(path, token="a key+with&escaping")
            assert "a+key%2Bwith%26escaping" in auth.login_url("http://localhost:8080")
            assert not ProxyAuthentication.load(path, disabled=True).enabled
            assert not path.exists()
            for value in ("", "bad\nkey"):
                with subtests.test(value=value), pytest.raises(ValueError):
                    ProxyAuthentication(value)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX pathname replacement")
    def test_path_replacement_cannot_change_the_validated_key(self, tmp_path):
        path = tmp_path / "auth-token"
        replacement = tmp_path / "replacement"
        path.write_text("original-key\n")
        path.chmod(0o600)
        replacement.write_text("replacement-key\n")
        replacement.chmod(0o600)
        original_fstat = os.fstat
        original_read_text = Path.read_text

        def replace_path():
            replacement.replace(path)

        def fstat_then_replace(descriptor):
            metadata = original_fstat(descriptor)
            replace_path()
            return metadata

        def replace_then_read(file_path, *args, **kwargs):
            replace_path()
            return original_read_text(file_path, *args, **kwargs)

        with (
            patch("azure_dev_proxy.auth.os.fstat", side_effect=fstat_then_replace),
            patch.object(Path, "read_text", replace_then_read),
        ):
            authentication = ProxyAuthentication.load(path)
        assert authentication.login_url("http://localhost:8080").endswith(
            "=original-key"
        )

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file protections")
    def test_symlink_replacement_before_open_is_rejected(self, tmp_path):
        path = tmp_path / "auth-token"
        target = tmp_path / "replacement"
        path.write_text("original-key\n")
        path.chmod(0o600)
        target.write_text("replacement-key\n")
        target.chmod(0o600)
        original_open = os.open

        def replace_then_open(file_path, flags):
            path.unlink()
            path.symlink_to(target)
            return original_open(file_path, flags)

        with (
            patch("azure_dev_proxy.auth.os.open", side_effect=replace_then_open),
            pytest.raises(OSError),
        ):
            ProxyAuthentication.load(path)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file protections")
    @pytest.mark.parametrize("kind", ["directory", "fifo", "other-owner"])
    def test_non_regular_or_foreign_owned_key_is_rejected(self, tmp_path, kind):
        path = tmp_path / "auth-token"
        if kind == "directory":
            path.mkdir(mode=0o700)
        elif kind == "fifo":
            os.mkfifo(path, mode=0o600)
        else:
            path.write_text("key\n")
            path.chmod(0o600)

        original_fstat = os.fstat

        def foreign_owner(descriptor):
            fields = list(original_fstat(descriptor))
            fields[4] = os.geteuid() + 1
            return os.stat_result(fields)

        with (
            patch(
                "azure_dev_proxy.auth.os.fstat",
                side_effect=foreign_owner if kind == "other-owner" else original_fstat,
            ),
            pytest.raises(ValueError, match="regular file|current user"),
        ):
            ProxyAuthentication.load(path)

    def test_reserved_query_fields_are_removed_without_reencoding_other_fields(self):
        path, tokens = ProxyAuthentication.strip_query_token(
            "/a%2Fb?x=%2f&azure%2Ddev-proxy-token=first%2Bkey&x=two&empty=&"
            "azure-dev-proxy-token=second+key&plus=+&"
        )
        assert path == "/a%2Fb?x=%2f&x=two&empty=&plus=+&"
        assert tokens == ("first+key", "second key")


class TestFooter:
    @pytest.mark.parametrize("mode", ["disabled", "explicit", "generated"])
    async def test_footer_warning_is_visible_only_without_token_authentication(
        self, mode
    ):
        authentication = (
            None
            if mode == "generated"
            else ProxyAuthentication(None if mode == "disabled" else "footer-key")
        )
        proxy = Proxy(
            TokenProvider(AsyncMock()),
            port=0,
            config=Config(()),
            authentication=authentication,
        )
        async with TestClient(TestServer(proxy.app, host="127.0.0.1")) as client:
            assert client.server.port is not None
            proxy.port = client.server.port
            path = (
                proxy.authentication.login_url(proxy.local_origin).removeprefix(
                    proxy.local_origin
                )
                if proxy.authentication.enabled
                else "/"
            )
            async with client.get(path) as response:
                assert response.status == 200
                page = await response.text()
        footer = re.search(r"<footer\b([^>]*)>(.*?)</footer>", page)
        assert footer is not None
        assert ("hidden" in footer[1]) == proxy.authentication.enabled
        assert 'class="warning"' in footer[1]
        assert "Token authentication disabled:" in footer[2]


class TestAuthentication:
    @pytest.fixture(autouse=True)
    async def authenticated_proxy(self, tls_contexts):
        self.received = []

        async def upstream(request):
            self.received.append(
                (request.raw_path, request.headers.copy(), await request.read())
            )
            return web.Response(body=self.received[-1][2] or b"ok")

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", upstream)
        self.api = TestServer(app, host="127.0.0.1", scheme="https")
        await self.api.start_server(ssl=tls_contexts[0])
        self.acquire = AsyncMock()
        self.auth = ProxyAuthentication("test-secret")
        self.proxy = Proxy(
            TokenProvider(self.acquire),
            port=0,
            authentication=self.auth,
            tls=False,
            config=Config((TokenRule("example.test"),)),
        )
        self.client = TestClient(
            TestServer(self.proxy.app, host="127.0.0.1"),
            cookie_jar=CookieJar(unsafe=True),
            requote_redirect_url=False,
        )
        await self.client.start_server()
        assert self.client.server.port is not None
        self.proxy.port = self.client.server.port
        self.route = f"/https://127.0.0.1:{self.api.port}/a%2Fb"
        self.origin = self.proxy.local_origin

        try:
            yield
        finally:
            await self.client.close()
            await self.api.close()

    async def login(self):
        response = await self.client.get(
            "/?azure-dev-proxy-token=test-secret",
            allow_redirects=False,
            headers={"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
        )
        assert response.status == 303
        assert response.headers["Location"] == "/"
        cookie = response.headers["Set-Cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie
        assert "Domain=" not in cookie
        assert "test-secret" not in cookie
        await response.read()
        return cookie.split(";", 1)[0]

    @pytest.mark.parametrize(
        ("path", "method", "headers", "data", "status", "message"),
        [
            (SESSION_PATH, "POST", {}, None, 405, "Method Not Allowed"),
            (LOGIN_PATH, "GET", {}, None, 405, "Method Not Allowed"),
            (
                LOGIN_PATH,
                "POST",
                {"Content-Type": "application/json"},
                "{}",
                400,
                "URL-encoded login form",
            ),
            (
                SESSION_PATH,
                "GET",
                {TOKEN_HEADER: "test-secret"},
                None,
                400,
                "single session return path",
            ),
            (
                SESSION_PATH + "?next=/&next=/foo",
                "GET",
                {TOKEN_HEADER: "test-secret"},
                None,
                400,
                "single session return path",
            ),
            (
                SESSION_PATH + "?next=/:session",
                "GET",
                {TOKEN_HEADER: "test-secret"},
                None,
                400,
                "Recursive session handoff",
            ),
        ],
    )
    async def test_invalid_login_and_handoff_requests(
        self, path, method, headers, data, status, message
    ):
        response = await self.client.request(method, path, headers=headers, data=data)
        assert response.status == status
        assert message in await response.text()
        assert not self.received
        self.acquire.assert_not_awaited()

    async def test_login_handler_independently_rejects_foreign_origin(self):
        request = make_mocked_request(
            "POST",
            LOGIN_PATH,
            headers={"Host": "localhost:8080", "Origin": "https://foo.example"},
        )
        with pytest.raises(web.HTTPForbidden, match="Forbidden") as error:
            await self.auth.authorize(request, ())
        assert error.value.text == "Local same-origin login required\n"

    async def test_handoff_requires_document_destination(self):
        request = make_mocked_request(
            "GET",
            "/foo",
            headers={"Host": "localhost:8080", "Sec-Fetch-Dest": "image"},
        )
        request[ROUTE_KEY] = "/foo"
        assert not self.auth.is_handoff(request, ("foo",))

    async def test_handoff_prunes_expired_entries_and_evicts_oldest_at_capacity(self):
        request = make_mocked_request("GET", "/", headers={"Host": "localhost:8080"})
        self.auth._handoffs = {
            "expired": ("http://127.0.0.1:8080", "/foo", 99),
            **{
                f"foo-{index}": ("http://127.0.0.1:8080", "/foo", 200)
                for index in range(1024)
            },
        }
        with patch("azure_dev_proxy.auth.time.monotonic", return_value=100):
            response = self.auth.handoff_response(request, "/foo?bar=1")
        assert len(self.auth._handoffs) == 1024
        assert "expired" not in self.auth._handoffs
        assert "foo-0" not in self.auth._handoffs
        assert "foo-1" in self.auth._handoffs
        assert response.status == 303
        assert response.headers["Location"].startswith(
            "http://127.0.0.1:8080/foo?bar=1&azure-dev-proxy-token=session-"
        )
        token = next(reversed(self.auth._handoffs))
        assert self.auth._handoffs[token] == (
            "http://127.0.0.1:8080",
            "/foo?bar=1",
            160,
        )

    async def test_all_proxy_surfaces_require_authentication_before_acquisition(
        self, subtests
    ):
        for path, method in (
            ("/", "GET"),
            ("/:config", "GET"),
            ("/:config/persisted", "POST"),
            ("/:graphiql/https://example.test/graphql", "GET"),
            ("/https://example.test/api", "POST"),
            (self.route, "POST"),
        ):
            with subtests.test(path=path, method=method):
                response = await self.client.request(method, path)
                assert response.status == 401
                if method == "GET":
                    assert 'type="password"' in await response.text()
                await response.read()
        assert not self.received
        self.acquire.assert_not_awaited()

    async def test_query_login_removes_only_reserved_fields_and_creates_session(
        self, caplog, subtests
    ):
        raw = (
            self.route
            + "?x=%2f&azure%2Ddev-proxy-token=test-secret&x=two&empty=&plus=+"
        )
        for method in ("GET", "HEAD"):
            self.client.session.cookie_jar.clear()
            caplog.clear()
            with (
                subtests.test(method=method),
                caplog.at_level("INFO", logger="azure_dev_proxy.proxy"),
            ):
                response = await self.client.request(
                    method,
                    URL(raw, encoded=True),
                    allow_redirects=False,
                )
                assert response.status == 200
                assert "Location" not in response.headers
                assert await response.read() == (b"ok" if method == "GET" else b"")
            assert any(
                record.name == "azure_dev_proxy.proxy"
                or record.name.startswith("azure_dev_proxy.proxy" + ".")
                for record in caplog.records
            )
            assert self.received[-1][0] == "/a%2Fb?x=%2f&x=two&empty=&plus=+"
            assert "test-secret" not in caplog.text
            assert TOKEN_PARAMETER not in caplog.text
        response = await self.client.post(self.route, data=b"session request")
        assert response.status == 200
        await response.read()
        assert "Cookie" not in self.received[-1][1]
        assert self.received[-1][2] == b"session request"

    async def test_query_key_cleans_browser_navigations_but_not_fetch_responses(self):
        route = self.route + "?x=%2f"
        raw = route + "&azure-dev-proxy-token=test-secret"
        response = await self.client.get(
            URL(raw, encoded=True),
            headers={
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            },
            allow_redirects=False,
        )
        assert response.status == 303
        assert response.headers["Location"] == route
        await response.read()
        assert not self.received
        self.client.session.cookie_jar.clear()
        response = await self.client.get(
            URL(raw, encoded=True),
            headers={
                "Origin": self.origin,
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            },
            allow_redirects=False,
        )
        assert response.status == 200
        assert "Location" not in response.headers
        assert await response.read() == b"ok"
        assert self.received[-1][0] == "/a%2Fb?x=%2f"

    async def test_post_credentials_and_referrers_are_not_forwarded(self):
        for mode in ("query", "header"):
            headers = {
                "Referer": self.origin + "/?azure-dev-proxy-token=test-secret&x=%2f"
            }
            route = self.route + "?keep=%2f"
            if mode == "query":
                route += "&azure-dev-proxy-token=test-secret"
            else:
                headers[TOKEN_HEADER] = "test-secret"
            response = await self.client.post(
                URL(route, encoded=True), headers=headers, data=b"body"
            )
            assert response.status == 200
            await response.read()
            path, seen, body = self.received[-1]
            assert path == "/a%2Fb?keep=%2f"
            assert body == b"body"
            assert TOKEN_HEADER not in seen
            assert seen["Referer"] == self.origin + "/?x=%2f"

    async def test_manual_login_returns_to_original_route_and_rejects_bad_inputs(self):
        path = self.route + "?x=%2f&empty="
        response = await self.client.get(URL(path, encoded=True))
        page = await response.text()
        match = re.search(r'name="next" value="([^"]*)"', page)
        assert match is not None
        next_path = html.unescape(match.group(1))
        assert next_path == path
        for token, status in (("wrong", 401), ("test-secret", 200)):
            response = await self.client.post(
                LOGIN_PATH,
                data={"token": token, "next": next_path},
                headers={"Origin": self.origin},
                allow_redirects=False,
            )
            assert response.status == status
            page = await response.text()
            if status == 200:
                assert "Location" not in response.headers
                assert 'http-equiv="refresh"' in page
                assert html.escape(next_path, quote=True) in page
                assert "test-secret" not in page
        response = await self.client.get(URL(path, encoded=True))
        assert response.status == 200
        await response.read()
        for next_path in (
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "/bad\npath",
        ):
            response = await self.client.post(
                LOGIN_PATH,
                data={"token": "test-secret", "next": next_path},
                headers={"Origin": self.origin},
                allow_redirects=False,
            )
            assert response.status == 400
            await response.read()
        response = await self.client.post(
            LOGIN_PATH,
            data={"token": "test-secret"},
            headers={"Origin": "http://evil.example"},
        )
        assert response.status == 403
        await response.read()

    async def test_direct_localhost_route_login_pairs_ip_before_forwarding(self):
        localhost = f"localhost:{self.proxy.port}"
        route = self.route + "?x=%2f&empty="
        response = await self.client.get(
            URL(route, encoded=True),
            headers={"Host": localhost},
            allow_redirects=False,
        )
        assert response.status == 401
        await response.read()
        response = await self.client.post(
            LOGIN_PATH,
            data={"token": "test-secret", "next": route},
            headers={"Host": localhost, "Origin": "http://" + localhost},
            allow_redirects=False,
        )
        assert response.status == 200
        assert "Location" not in response.headers
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        assert html.escape(route, quote=True) in await response.text()
        response = await self.client.get(
            URL(route, encoded=True),
            headers={"Host": localhost, "Cookie": cookie},
            allow_redirects=False,
        )
        location = URL(response.headers["Location"], encoded=True)
        assert location.host == "127.0.0.1"
        assert TOKEN_PARAMETER in location.query
        await response.read()
        response = await self.client.get(
            URL(location.raw_path_qs, encoded=True),
            allow_redirects=False,
        )
        assert response.status == 200
        assert 'http-equiv="refresh"' in await response.text()
        response = await self.client.get(URL(route, encoded=True))
        assert response.status == 200
        await response.read()
        assert self.received[-1][0] == "/a%2Fb?x=%2f&empty="

    async def test_sessions_survive_restart_but_not_key_changes_or_tampering(self):
        cookie = await self.login()
        self.proxy.authentication = ProxyAuthentication("test-secret")
        response = await self.client.get("/")
        assert response.status == 200
        await response.read()
        self.proxy.authentication = ProxyAuthentication("different-secret")
        response = await self.client.get("/")
        assert response.status == 401
        await response.read()
        response = await self.client.get("/", headers={"Cookie": cookie + "tampered"})
        assert response.status == 401
        await response.read()

    async def test_invalid_duplicate_and_cross_origin_credentials_are_rejected(self):
        await self.login()
        for query, status in (
            ("azure-dev-proxy-token=wrong", 401),
            (
                "azure-dev-proxy-token=test-secret&azure-dev-proxy-token=test-secret",
                400,
            ),
        ):
            response = await self.client.get("/?" + query, allow_redirects=False)
            assert response.status == status
            await response.read()
        response = await self.client.post(
            self.route + "?azure-dev-proxy-token=test-secret",
            headers={"Origin": "https://evil.example"},
        )
        assert response.status == 403
        await response.read()
        assert not self.received

    async def test_preflight_is_public_but_actual_requests_require_authentication(self):
        self.proxy.config = Config(
            self.proxy.config.token_rules, ("http://localhost:3000",)
        )
        response = await self.client.options(
            self.route,
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": TOKEN_HEADER,
            },
        )
        assert response.status == 204
        await response.read()
        response = await self.client.post(
            self.route, headers={"Origin": "http://localhost:3000"}
        )
        assert response.status == 401
        await response.read()
        assert not self.received
        self.acquire.assert_not_awaited()

    async def test_disabled_auth_still_strips_credentials(self):
        self.proxy.authentication = ProxyAuthentication(None)
        response = await self.client.post(
            URL(self.route + "?azure-dev-proxy-token=discard&x=%2f", encoded=True),
            headers={TOKEN_HEADER: "discard", "Cookie": "discard=also"},
            data=b"body",
        )
        assert response.status == 200
        await response.read()
        path, headers, body = self.received[-1]
        assert path == "/a%2Fb?x=%2f"
        assert TOKEN_HEADER not in headers
        assert "Cookie" not in headers
        assert body == b"body"

    async def test_cross_host_handoff_is_single_use_and_destination_bound(self):
        await self.login()
        port = self.proxy.port
        localhost = f"localhost:{port}"
        navigation = {
            "Host": localhost,
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-User": "?1",
        }
        response = await self.client.get("/", headers=navigation, allow_redirects=False)
        assert response.status == 303
        location = URL(response.headers["Location"])
        assert location.host == "127.0.0.1"
        await response.read()
        response = await self.client.get(location.path_qs, allow_redirects=False)
        assert response.status == 303
        handoff = URL(response.headers["Location"])
        assert handoff.host == "localhost"
        assert "test-secret" not in str(handoff)
        await response.read()
        for host, route in (
            (f"127.0.0.1:{port}", handoff.path_qs),
            (localhost, "/wrong?" + handoff.query_string),
        ):
            response = await self.client.get(
                route, headers={"Host": host}, allow_redirects=False
            )
            assert response.status == 401
            await response.read()
        response = await self.client.post(handoff.path_qs, headers={"Host": localhost})
        assert response.status == 401
        await response.read()
        response = await self.client.get(
            handoff.path_qs,
            headers={**navigation, "Origin": "null"},
            allow_redirects=False,
        )
        assert response.status == 200
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        assert 'http-equiv="refresh"' in await response.text()
        response = await self.client.get(
            "/", headers={"Host": localhost, "Cookie": cookie}
        )
        assert response.status == 200
        await response.read()
        response = await self.client.get(
            handoff.path_qs, headers={"Host": localhost}, allow_redirects=False
        )
        assert response.status == 401
        await response.read()
        response = await self.client.get(
            "/",
            headers={
                "Host": localhost,
                "Cookie": cookie,
                "Origin": "null",
            },
        )
        assert response.status == 403
        await response.read()

    async def test_expired_handoff_cannot_establish_session(self):
        await self.login()
        response = await self.client.get(
            SESSION_PATH + "?" + urlencode({"next": "/"}), allow_redirects=False
        )
        handoff = URL(response.headers["Location"])
        await response.read()
        with patch("azure_dev_proxy.auth.time") as clock:
            clock.monotonic.return_value = float("inf")
            response = await self.client.get(
                handoff.path_qs,
                headers={"Host": f"localhost:{self.proxy.port}"},
                allow_redirects=False,
            )
        assert response.status == 401
        await response.read()


class TestIdleShutdown:
    async def test_idle_exit_closes_owned_tokens_and_upstream_session(self):
        tokens = TokenProvider(AsyncMock())
        proxy = Proxy(
            tokens,
            port=8080,
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        await asyncio.wait_for(proxy._serve([], idle_timeout=0.01), 1)
        assert tokens.closed
        assert proxy.session is None

    async def test_default_does_not_schedule_idle_shutdown(self):
        proxy = Proxy(
            TokenProvider(AsyncMock()),
            port=8080,
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        proxy.activity.wait_for_idle = AsyncMock()
        runner = MagicMock(setup=AsyncMock(), cleanup=AsyncMock())
        loop = asyncio.get_running_loop()
        with (
            patch("azure_dev_proxy.proxy.web.AppRunner", return_value=runner),
            patch.object(
                loop,
                "add_signal_handler",
                side_effect=lambda _, callback: loop.call_soon(callback),
            ),
            patch.object(loop, "remove_signal_handler"),
        ):
            await asyncio.wait_for(proxy._serve([]), 1)
        proxy.activity.wait_for_idle.assert_not_awaited()
        runner.cleanup.assert_awaited_once()

    async def test_windows_signal_fallback_is_restored(self):
        proxy = Proxy(
            TokenProvider(AsyncMock()),
            port=8080,
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        runner = MagicMock(setup=AsyncMock(), cleanup=AsyncMock())
        loop = asyncio.get_running_loop()

        def previous(*_):
            return None

        calls = []

        def install(signum, handler):
            calls.append((signum, handler))
            if handler is not previous:
                loop.call_soon(handler, signum, None)
            return previous

        with (
            patch("azure_dev_proxy.proxy.web.AppRunner", return_value=runner),
            patch.object(
                loop,
                "add_signal_handler",
                side_effect=NotImplementedError,
            ),
            patch("azure_dev_proxy.proxy.signal.signal", side_effect=install),
        ):
            await asyncio.wait_for(proxy._serve([]), 1)
        assert len(calls) == 4
        assert calls[-1][1] is previous
