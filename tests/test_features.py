from __future__ import annotations

import asyncio
import errno
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import replace
from functools import partial
from io import StringIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

from azure_dev_proxy.auth import ProxyAuthentication
from azure_dev_proxy.__main__ import main
from azure_dev_proxy.config import Config, TokenRule
from azure_dev_proxy.idle_timer import IdleTracker
from azure_dev_proxy.proxy import Proxy
from azure_dev_proxy.routers.management import MANAGEMENT_KEY
from azure_dev_proxy.routers.utils import parse_target, rewrite_refresh, rewrite_url
from azure_dev_proxy.listeners import LoopbackListeners
from azure_dev_proxy.tokens import TokenProvider


class TestCLI:
    def test_config_check_does_not_initialize_proxy_or_authentication(self, tmp_path):
        path = tmp_path / "config.json"
        with (
            patch.object(
                sys,
                "argv",
                ["azure-dev-proxy", "--config", str(path), "--check-config"],
            ),
            patch("azure_dev_proxy.__main__.Proxy") as proxy,
        ):
            main()
        assert path.is_file()
        assert not (tmp_path / "auth-token").exists()
        proxy.assert_not_called()

    def test_root_startup_is_rejected_before_configuration_is_loaded(self, capsys):
        with (
            patch.object(sys, "argv", ["azure-dev-proxy"]),
            patch("azure_dev_proxy.__main__.os.geteuid", return_value=0, create=True),
            patch("azure_dev_proxy.__main__.Config.load") as load,
            patch("azure_dev_proxy.__main__.Proxy.serve") as serve,
            pytest.raises(SystemExit) as error,
        ):
            main()
        assert error.value.code == 1
        assert "Run azure-dev-proxy as a non-root user" in capsys.readouterr().err
        load.assert_not_called()
        serve.assert_not_called()

    @pytest.mark.parametrize(
        ("disabled", "terminal"), [(True, True), (True, False), (False, True)]
    )
    def test_disabled_authentication_warning_is_red_only_on_terminals(
        self, disabled, terminal
    ) -> None:
        stderr = StringIO()
        arguments = ["azure-dev-proxy", "--port", "8181", "--idle-timeout", "2"]
        arguments += ["--no-auth"] if disabled else ["--token", "cli-test-key"]
        with (
            patch.object(sys, "argv", arguments),
            patch.object(sys, "stderr", stderr),
            patch.object(stderr, "isatty", return_value=terminal),
            patch(
                "azure_dev_proxy.__main__.os.geteuid", return_value=1000, create=True
            ),
            patch("azure_dev_proxy.__main__.Config.load", return_value=Config(())),
            patch("azure_dev_proxy.__main__.Proxy.serve") as serve,
        ):
            main()
        serve.assert_called_once_with(8181, idle_timeout=2)
        expected = (
            "WARNING: Proxy authentication is disabled "
            "(other users of this machine, including applications, "
            "can use this proxy without authorization)"
        )
        if disabled:
            if terminal:
                expected = f"\x1b[31m{expected}\x1b[0m"
            assert stderr.getvalue() == expected + "\n"
        else:
            assert stderr.getvalue() == ""


class TestServe:
    @pytest.mark.parametrize("failure", [None, "loop", "setup"])
    def test_listeners_precede_the_loop_and_close_on_exit(
        self, failure, capsys
    ) -> None:
        tokens = TokenProvider(AsyncMock())
        proxy = Proxy(
            tokens,
            config=Config(()),
            authentication=ProxyAuthentication(None),
        )
        assert proxy.port == 0
        original_bind = LoopbackListeners._bind
        original_run = asyncio.run
        sockets = []
        ports = []

        def bind(listeners, family, host):
            run.assert_not_called()
            assert "app" not in proxy.__dict__
            original_bind(listeners, family, host)
            listener = listeners._sockets[-1]
            sockets.append(listener)
            ports.append(listener.getsockname()[1])

        def run_owned_loop(coroutine):
            assert sockets
            assert proxy.port == ports[0] > 0
            assert len(set(ports)) == 1
            if failure == "loop":
                coroutine.close()
                raise RuntimeError("Loop startup failed")
            return original_run(coroutine)

        setup = (
            patch(
                "azure_dev_proxy.proxy.web.AppRunner.setup",
                new=AsyncMock(side_effect=RuntimeError("App startup failed")),
            )
            if failure == "setup"
            else nullcontext()
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(LoopbackListeners, "_bind", bind),
            patch(
                "azure_dev_proxy.proxy.asyncio.run", side_effect=run_owned_loop
            ) as run,
            setup,
        ):
            if failure is None:
                proxy.serve(0, idle_timeout=0.01)
            else:
                with pytest.raises(RuntimeError, match="startup failed"):
                    proxy.serve(0, idle_timeout=0.01)
        run.assert_called_once()
        assert all(listener.fileno() == -1 for listener in sockets)
        assert proxy.session is None
        if failure is None:
            assert tokens.closed
            assert (
                f"Azure proxy listening at http://localhost:{proxy.port}"
                in capsys.readouterr().out
            )


class TestConfiguration:
    @pytest.mark.parametrize(
        "text",
        [
            "not json",
            '{"token_rules":[],"token_rules":[]}',
            '{"token_rules":[{"host":"one.example","host":"two.example"}]}',
        ],
    )
    def test_invalid_json_is_rejected_without_replacing_file(
        self, tmp_path, text
    ) -> None:
        path = tmp_path / "config.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError):
            Config.load(path)
        with pytest.raises(ValueError):
            Config.update_rule(path, TokenRule("new.example"))
        assert path.read_text(encoding="utf-8") == text

    def test_cli_validates_selected_file_without_loading_defaults(
        self, tmp_path
    ) -> None:
        path = tmp_path / "selected.json"
        original = '{"token_rules":[],"trusted_origins":["https://example.com"]}'
        path.write_text(original, encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "azure_dev_proxy",
                "--config",
                str(path),
                "--check-config",
            ],
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert path.read_text(encoding="utf-8") == original

    @pytest.mark.skipif(
        os.name == "nt", reason="POSIX symlink and permission semantics"
    )
    def test_persisted_updates_follow_symlinks_and_preserve_file_permissions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "actual.json"
            target.write_text('{"token_rules":[]}', encoding="utf-8")
            target.chmod(0o640)
            path = Path(directory) / "config.json"
            path.symlink_to(target)
            saved = Config.update_rule(path, TokenRule("Example.COM."))
            assert path.is_symlink()
            assert target.stat().st_mode & 511 == 416
            assert saved == Config.load(target)
            assert saved.token_rules == (TokenRule("example.com"),)

    def test_json_is_strict_and_missing_files_are_installed_once(
        self, subtests
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested/config.json"
            with ThreadPoolExecutor(max_workers=4) as pool:
                configurations = list(pool.map(lambda _: Config.load(path), range(8)))
            assert all((config == configurations[0] for config in configurations))
            assert configurations[0] == Config.defaults()
            path.write_text('{"token_rules":[]}', encoding="utf-8")
            assert Config.load(path).token_rules == ()
            assert json.loads(path.read_text())["token_rules"] == []
            for value in [
                {"token_rules": [], "unknown": True},
                {"token_rules": {}},
                {"token_rules": [{"host": "a", "unknown": True}]},
                {"token_rules": [{"host": 1}]},
                {"token_rules": [{"host": "a", "resource": 1}]},
                [],
            ]:
                with subtests.test(value=value), pytest.raises(ValueError):
                    Config.parse(value)

    def test_existing_configuration_is_not_expanded_with_new_defaults(self, tmp_path):
        path = tmp_path / "config.json"
        original = (
            '{"token_rules":[{"host":"*.azure.net"},{"host":"*.azure-test.net"}],'
            '"trusted_origins":["https://foo.example"]}\n'
        )
        path.write_text(original, encoding="utf-8")
        config = Config.load(path)
        assert config == Config(
            (TokenRule("*.azure.net"), TokenRule("*.azure-test.net")),
            ("https://foo.example",),
        )
        assert config.resource_for("https://foo.blob.core.windows.net") is None
        assert path.read_text(encoding="utf-8") == original

    def test_resource_validation_rejects_delimiters_and_controls(
        self, subtests
    ) -> None:
        for resource in [
            "https://a/?",
            "https://a/#",
            "https://a/path with spaces",
            "https://a/\n",
        ]:
            with subtests.test(resource=resource), pytest.raises(ValueError):
                TokenRule("a", resource)

    def test_trusted_origin_configuration_is_exact_and_normalized(
        self, subtests
    ) -> None:
        value = {"token_rules": []}
        assert Config.parse(value).trusted_origins == ()
        config = Config.parse(
            value
            | {
                "trusted_origins": [
                    "HTTPS://Example.COM:443",
                    "http://localhost:3000",
                    "http://[::1]:80",
                    "http://example.com:443",
                ]
            }
        )
        assert config.trusted_origins == (
            "https://example.com",
            "http://localhost:3000",
            "http://[::1]",
            "http://example.com:443",
        )
        assert Config.parse(config.as_dict()) == config
        for origins in (
            None,
            "https://example.com",
            [1],
            ["null"],
            ["*"],
            ["https://*.example.com"],
            ["https://example.com/"],
            ["https://example.com/path"],
            ["https://example.com?"],
            ["https://example.com#"],
            ["https://user@example.com"],
            ["https://example.com:0"],
            ["https://example.com:65536"],
            ["ftp://example.com"],
            ["https://example.com\n"],
        ):
            with subtests.test(origins=origins), pytest.raises(ValueError):
                Config.parse(value | {"trusted_origins": origins})

    def test_idna_configuration_keeps_trusted_origins_distinct(self) -> None:
        config = Config.parse(
            {
                "token_rules": [],
                "trusted_origins": ["https://fa\u00df.example", "https://fass.example"],
            }
        )
        assert config.trusted_origins == (
            "https://xn--fa-hia.example",
            "https://fass.example",
        )
        assert Config.parse(config.as_dict()) == config

    def test_explicit_https_and_navigation_preserve_route_style_and_escaping(
        self,
        subtests,
    ) -> None:
        for prefix in ["", "https://", "HTTPS://"]:
            target = parse_target(
                f"/{prefix}EXAMPLE.com:444/a%2Fb?q=%2f&q=two&empty=&plus=+"
            )
            assert (
                str(target) == "https://example.com:444/a%2Fb?q=%2f&q=two&empty=&plus=+"
            )
            explicit = bool(prefix)
            scheme = "https://" if explicit else ""
            assert (
                rewrite_url(
                    "../next?q=%2F#fragment",
                    target,
                    "http://127.0.0.1:8080",
                    explicit_scheme=explicit,
                )
                == f"http://127.0.0.1:8080/{scheme}example.com:444/next?q=%2F#fragment"
            )
            assert (
                rewrite_refresh(
                    "1; url=https://other.example/a",
                    target,
                    "http://127.0.0.1:8080",
                    explicit_scheme=explicit,
                )
                == f"1; url=http://127.0.0.1:8080/{scheme}other.example/a"
            )
        assert (
            str(parse_target("/HTTP://Example.COM:80/a%2Fb?q=%2f"))
            == "http://example.com/a%2Fb?q=%2f"
        )
        for path in ["/ftp://example.com/a", "/https:/example.com/a", "/https:///a"]:
            with subtests.test(path=path), pytest.raises(ValueError):
                parse_target(path)

    def test_cli_help_and_invalid_arguments_never_create_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for arguments, code in [
                (["--help"], 0),
                (["--version"], 0),
                (["--port", "0"], 2),
                (["--port", "65536"], 2),
                (["--idle-timeout", "-1"], 2),
                (["--idle-timeout", "not-a-number"], 2),
            ]:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "azure_dev_proxy",
                        "--config",
                        str(path),
                        *arguments,
                    ],
                    capture_output=True,
                    check=False,
                )
                assert result.returncode == code, result.stderr
                assert not path.exists()
                if arguments == ["--help"]:
                    assert b"azure-dev-proxy" in result.stdout


class TestManagement:
    @pytest.fixture(autouse=True)
    async def management_proxy(self, tmp_path):
        self.path = tmp_path / "config.json"
        self.path.write_text(
            json.dumps(
                {
                    "token_rules": [
                        {"host": "base.example", "resource": "https://base.example"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.acquire = AsyncMock()
        tokens = TokenProvider(self.acquire)
        self.proxy = Proxy(
            tokens,
            port=0,
            authentication=ProxyAuthentication(None),
            config=Config.load(self.path),
            config_path=self.path,
        )
        self.client = TestClient(TestServer(self.proxy.app, host="127.0.0.1"))
        await self.client.start_server()
        assert self.client.server.port is not None
        self.proxy.port = self.client.server.port
        self.edit_host = f"localhost:{self.proxy.port}"
        self.edit_origin = "http://" + self.edit_host
        self.ip_origin = f"http://127.0.0.1:{self.proxy.port}"
        async with self.client.get("/", headers={"Host": self.edit_host}) as response:
            assert response.status == 200
            assert response.headers["Cache-Control"] == "no-store"
            assert (
                "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
            )
            page = await response.text()
        match = re.search(r'name="azure-dev-proxy-csrf" content="([a-f0-9]{64})"', page)
        assert match is not None
        self.csrf = match.group(1)
        self.edit_headers = {
            "Host": self.edit_host,
            "Origin": self.edit_origin,
            "X-Azure-Proxy-CSRF": self.csrf,
        }

        try:
            yield
        finally:
            await self.client.close()

    @pytest.mark.parametrize(
        ("path", "method", "allowed"),
        [
            ("/", "POST", {"GET", "HEAD"}),
            ("/:app.js", "DELETE", {"GET", "HEAD"}),
            ("/:config", "PUT", {"GET", "HEAD", "POST", "DELETE"}),
            ("/:config/persisted", "GET", {"POST", "DELETE"}),
        ],
    )
    async def test_management_methods_are_explicitly_restricted(
        self, path, method, allowed
    ):
        response = await self.client.request(method, path, headers=self.edit_headers)
        assert response.status == 405
        assert set(response.headers["Allow"].split(",")) == allowed
        assert await response.text() == "405: Method Not Allowed"
        self.acquire.assert_not_awaited()

    async def test_missing_origin_cannot_modify_overrides(self):
        headers = self.edit_headers.copy()
        del headers["Origin"]
        response = await self.client.post(
            "/:config", headers=headers, json={"host": "foo.example"}
        )
        assert response.status == 403
        assert "Same-origin JSON and CSRF token required" in await response.text()
        assert not self.proxy.app[MANAGEMENT_KEY]._overrides

    @pytest.mark.parametrize(
        "value", [[], {}, {"host": "foo.example", "resource": "https://bar.example"}]
    )
    async def test_persisted_operations_require_only_a_hostname(self, value):
        original = self.path.read_text()
        response = await self.client.post(
            "/:config/persisted", headers=self.edit_headers, json=value
        )
        assert response.status == 400
        assert (
            await response.text() == "Invalid or oversized hostname/resource override\n"
        )
        assert self.path.read_text() == original
        assert not self.proxy.app[MANAGEMENT_KEY]._overrides

    async def test_read_only_ui_links_to_edit_origin_without_exposing_token(
        self,
    ) -> None:
        async with self.client.get("/") as response:
            page = await response.text()
            assert 'data-editable="false"' in page
            assert f'href="{self.edit_origin}/"' in page
            assert self.csrf not in page
            assert "Access-Control-Allow-Origin" not in response.headers
        async with self.client.get("/:config") as response:
            data = await response.json()
            assert not data["editable"]
            assert data["base_rules"][0]["host"] == "base.example"
        async with self.client.get("/:app.js") as response:
            script = await response.text()
            assert "textContent" in script
            assert "innerHTML" not in script
        async with self.client.post(
            "/:config",
            json={"host": "evil.example"},
            headers={"Origin": self.ip_origin, "X-Azure-Proxy-CSRF": self.csrf},
        ) as response:
            assert response.status == 403

    async def test_unknown_special_routes_are_not_forwarded(self, subtests) -> None:
        for path in (
            "/:unknown",
            "/:config/unknown",
            "/:graphiql",
            "/:graphql/https://example.com/graphql",
        ):
            with subtests.test(path=path):
                async with self.client.get(path) as response:
                    assert response.status == 404
                    assert "Access-Control-Allow-Origin" not in response.headers
        self.acquire.assert_not_awaited()

    async def test_user_initiated_editor_navigation_is_allowed_but_not_api_access(
        self,
    ) -> None:
        headers = {
            "Host": self.edit_host,
            "Referer": self.ip_origin + "/",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-User": "?1",
        }
        async with self.client.get("/", headers=headers) as response:
            assert response.status == 200
            assert self.csrf in await response.text()
            assert response.headers["Referrer-Policy"] == "strict-origin"
        for path in ("/", "/:config", "/:app.js"):
            for changes in (
                {"Sec-Fetch-User": ""},
                {"Sec-Fetch-Dest": "iframe"},
                {"Sec-Fetch-Mode": "cors"},
                {"Origin": "https://attacker.example"},
            ):
                async with self.client.get(path, headers=headers | changes) as response:
                    assert response.status == 403
            if path != "/":
                async with self.client.get(path, headers=headers) as response:
                    assert response.status == 403
        async with self.client.post(
            "/:config",
            json={"host": "attacker.example"},
            headers=headers | self.edit_headers,
        ) as response:
            assert response.status == 403

    async def test_overrides_precede_base_and_remove_restores_base(self) -> None:
        for host, resource in [
            ("*.example", "https://broad.example"),
            ("*.base.example", "https://wildcard.example"),
            ("BASE.EXAMPLE.", None),
        ]:
            async with self.client.post(
                "/:config",
                json={"host": host, "resource": resource},
                headers=self.edit_headers,
            ) as response:
                assert response.status == 200, await response.text()
                data = await response.json()
            if host == "*.example":
                assert (
                    self.proxy.app[MANAGEMENT_KEY].resource_for(
                        "https://base.example", self.proxy.config
                    )
                    == "https://broad.example"
                )
        assert data["effective_rules"][0]["host"] == "base.example"
        assert (
            self.proxy.app[MANAGEMENT_KEY].resource_for(
                "https://base.example:444", self.proxy.config
            )
            == "https://base.example:444"
        )
        assert (
            self.proxy.app[MANAGEMENT_KEY].resource_for(
                "https://x.base.example", self.proxy.config
            )
            == "https://wildcard.example"
        )
        assert (
            self.proxy.app[MANAGEMENT_KEY].resource_for(
                "https://x.example", self.proxy.config
            )
            == "https://broad.example"
        )
        for host in ["base.example", "*.base.example", "*.example"]:
            async with self.client.delete(
                "/:config",
                json={"host": host},
                headers=self.edit_headers,
            ) as response:
                assert response.status == 200
        assert (
            self.proxy.app[MANAGEMENT_KEY].resource_for(
                "https://base.example", self.proxy.config
            )
            == "https://base.example"
        )

    async def test_promoting_rule_replaces_persisted_mapping_and_keeps_other_settings(
        self,
    ) -> None:
        current = self.proxy.config
        original = {
            "token_rules": [
                {"host": "BASE.EXAMPLE.", "resource": "https://old.example"},
                {"host": "Unrelated.Example."},
            ],
            "trusted_origins": ["HTTPS://Other.Example:443"],
            "query_string_substitutions_by_host": {"ignored": [{"pattern": "["}]},
        }
        self.path.write_text(json.dumps(original), encoding="utf-8")
        for rule in [
            {"host": "BASE.EXAMPLE.", "resource": "https://new.example"},
            {"host": "temporary.example"},
        ]:
            async with self.client.post(
                "/:config",
                json=rule,
                headers=self.edit_headers,
            ) as response:
                assert response.status == 200
        assert json.loads(self.path.read_text()) == original
        async with self.client.post(
            "/:config/persisted",
            json={"host": "BASE.EXAMPLE."},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 200, await response.text()
            snapshot = await response.json()
        assert [rule["host"] for rule in snapshot["overrides"]] == ["temporary.example"]
        assert json.loads(self.path.read_text()) == {
            "token_rules": [
                {"host": "Unrelated.Example."},
                {"host": "base.example", "resource": "https://new.example"},
            ],
            "trusted_origins": original["trusted_origins"],
        }
        assert (
            self.proxy.app[MANAGEMENT_KEY].resource_for(
                "https://base.example", self.proxy.config
            )
            == "https://new.example"
        )
        reloaded = Config.load(self.path)
        assert self.proxy.config is not current
        assert self.proxy.config.token_rules == reloaded.token_rules
        assert self.proxy.config.trusted_origins == current.trusted_origins
        assert snapshot["trusted_origins"] == list(current.trusted_origins)
        assert not self.proxy.is_trusted_origin("https://other.example")
        assert reloaded.trusted_origins == ("https://other.example",)
        restarted = Proxy(
            TokenProvider(AsyncMock()),
            port=0,
            config=reloaded,
            config_path=self.path,
        )
        assert (
            restarted.app[MANAGEMENT_KEY].resource_for(
                "https://base.example", restarted.config
            )
            == "https://new.example"
        )

    async def test_deleting_last_persisted_rule_survives_reload_and_keeps_temporary_rules(
        self,
    ) -> None:
        async with self.client.post(
            "/:config",
            json={"host": "temporary.example"},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 200
        async with self.client.delete(
            "/:config/persisted",
            json={"host": "BASE.EXAMPLE."},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 200
            snapshot = await response.json()
        assert snapshot["base_rules"] == []
        assert [rule["host"] for rule in snapshot["overrides"]] == ["temporary.example"]
        assert self.proxy.config.token_rules == ()
        assert Config.load(self.path).token_rules == ()
        assert (
            self.proxy.app[MANAGEMENT_KEY].resource_for(
                "https://base.example", self.proxy.config
            )
            is None
        )

    async def test_failed_persisted_writes_preserve_disk_rules_and_overrides(
        self,
        subtests,
    ) -> None:
        async with self.client.post(
            "/:config",
            json={"host": "base.example", "resource": "https://new.example"},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 200
        original = self.path.read_bytes()
        original_config = self.proxy.config
        for method in ("POST", "DELETE"):
            for error, status in (
                (OSError("disk full"), 500),
                (PermissionError("read-only"), 403),
            ):
                with (
                    subtests.test(method=method, error=type(error).__name__),
                    patch(
                        "azure_dev_proxy.config.os.replace",
                        side_effect=error,
                    ),
                ):
                    async with self.client.request(
                        method,
                        "/:config/persisted",
                        json={"host": "base.example"},
                        headers=self.edit_headers,
                    ) as response:
                        assert response.status == status
                        await response.read()
                assert self.path.read_bytes() == original
                assert self.proxy.config is original_config
                assert set(self.path.parent.iterdir()) == {self.path}
                assert (
                    self.proxy.app[MANAGEMENT_KEY].resource_for(
                        "https://base.example", self.proxy.config
                    )
                    == "https://new.example"
                )
        self.path.write_text("invalid json", encoding="utf-8")
        async with self.client.post(
            "/:config/persisted",
            json={"host": "base.example"},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 409
        assert self.path.read_text() == "invalid json"
        assert self.proxy.config is original_config

    async def test_persisted_changes_require_editor_origin_csrf_and_existing_override(
        self,
    ) -> None:
        original = self.path.read_bytes()
        for method in ("POST", "DELETE"):
            for headers in (
                {"Origin": self.ip_origin, "X-Azure-Proxy-CSRF": self.csrf},
                {"Host": self.edit_host, "Origin": self.edit_origin},
                self.edit_headers | {"Origin": self.ip_origin},
                self.edit_headers | {"X-Azure-Proxy-CSRF": "wrong"},
            ):
                async with self.client.request(
                    method,
                    "/:config/persisted",
                    json={"host": "base.example"},
                    headers=headers,
                ) as response:
                    assert response.status == 403
        async with self.client.post(
            "/:config/persisted",
            json={"host": "missing.example"},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 404
        assert self.path.read_bytes() == original
        self.proxy.config_path = None
        async with self.client.delete(
            "/:config/persisted",
            json={"host": "base.example"},
            headers=self.edit_headers,
        ) as response:
            assert response.status == 409
        assert self.path.read_bytes() == original

    async def test_configuration_boundaries_and_validation(self) -> None:
        self.proxy.config = replace(
            self.proxy.config, trusted_origins=("https://attacker.example",)
        )
        for value in [
            {"host": "bad host"},
            {"host": "a", "resource": "http://a"},
            {"host": "a", "resource": "https://user@a"},
            {"host": "a", "unknown": True},
            {"resource": "https://a"},
        ]:
            async with self.client.post(
                "/:config", json=value, headers=self.edit_headers
            ) as response:
                assert response.status == 400
        async with self.client.post(
            "/:config",
            data="x" * 17000,
            headers=self.edit_headers | {"Content-Type": "application/json"},
        ) as response:
            assert response.status == 400
        for headers in [
            {"Host": self.edit_host},
            {"Host": self.edit_host, "Origin": self.edit_origin},
            self.edit_headers | {"Origin": self.ip_origin},
            self.edit_headers | {"X-Azure-Proxy-CSRF": "wrong"},
        ]:
            async with self.client.post(
                "/:config", json={"host": "a"}, headers=headers
            ) as response:
                assert response.status == 403
        for path in ["/", "/:config", "/:app.js"]:
            async with self.client.get(
                path, headers={"Origin": "https://attacker.example"}
            ) as response:
                assert response.status == 403
                assert "Access-Control-Allow-Origin" not in response.headers
        async with self.client.get(
            "/", headers={"Host": self.edit_host, "Origin": self.ip_origin}
        ) as response:
            assert response.status == 403
        async with self.client.options(
            "/:config",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
            },
        ) as response:
            assert response.status == 403
        async with self.client.get(
            "/", headers={"Host": "attacker.example"}
        ) as response:
            assert response.status == 400

    async def test_localhost_forwarding_redirect_preserves_method_and_raw_route(
        self,
    ) -> None:
        for method in ["GET", "POST"]:
            async with self.client.request(
                method,
                URL("/https://example.com/a%2Fb?q=%2f&q=two", encoded=True),
                headers={"Host": self.edit_host},
                data=b"body",
                allow_redirects=False,
            ) as response:
                assert response.status == 307
                assert (
                    response.headers["Location"]
                    == self.ip_origin + "/https://example.com/a%2Fb?q=%2f&q=two"
                )

    async def test_idle_shutdown_ignores_unused_keep_alive_connections(self) -> None:
        async with self.client.get("/") as response:
            await response.read()
        await asyncio.wait_for(self.proxy.activity.wait_for_idle(0.03), 1)


class TestActivity:
    async def test_nested_requests_remain_active_until_the_last_finishes(self):
        tracker = IdleTracker()
        with tracker.request():
            with tracker.request():
                waiter = asyncio.create_task(tracker.wait_for_idle(0))
                await asyncio.sleep(0)
                assert not waiter.done()
            await asyncio.sleep(0)
            assert not waiter.done()
        await asyncio.wait_for(waiter, 1)
        with pytest.raises(web.HTTPServiceUnavailable):
            with tracker.request():
                pytest.fail("Shutdown must reject new requests")

    async def test_active_requests_prevent_exit_and_completion_resets_timeout(
        self,
    ) -> None:
        activity = IdleTracker()
        with activity.request(), pytest.raises(TimeoutError):
            await asyncio.wait_for(activity.wait_for_idle(0.02), 0.05)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(activity.wait_for_idle(0.05), 0.01)
        await activity.wait_for_idle(0.02)
        with pytest.raises(web.HTTPServiceUnavailable) as error:
            with activity.request():
                pytest.fail("Shutdown must not admit another request")
        assert error.value.status == 503


class TestListener:
    def test_activation_rejects_another_process_pid(self):
        with (
            patch.dict(
                os.environ,
                {"LISTEN_PID": str(os.getpid() + 1), "LISTEN_FDS": "1"},
            ),
            patch("azure_dev_proxy.listeners.socket.socket") as socket_factory,
            pytest.raises(ValueError, match="activation PID"),
        ):
            with LoopbackListeners(8080):
                pytest.fail("Invalid activation must not start")
        socket_factory.assert_not_called()

    @pytest.mark.parametrize("kind", ["family", "datagram", "not-listening"])
    def test_activation_rejects_non_tcp_listeners_and_closes_them(self, kind):
        listener = MagicMock()
        listener.family = socket.AF_UNIX if kind == "family" else socket.AF_INET
        listener.getsockopt.side_effect = (
            [socket.SOCK_DGRAM] if kind == "datagram" else [socket.SOCK_STREAM, 0]
        )
        with (
            patch.dict(os.environ, {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}),
            patch("azure_dev_proxy.listeners.socket.socket", return_value=listener),
            pytest.raises(ValueError, match="listening TCP sockets"),
        ):
            with LoopbackListeners(8080):
                pytest.fail("Invalid listener must not start")
        listener.close.assert_called_once()

    def test_only_ipv6_unavailability_permits_ipv4_fallback(
        self, caplog, subtests
    ) -> None:
        original = LoopbackListeners._bind
        unavailable = {
            errno.EAFNOSUPPORT,
            errno.EPROTONOSUPPORT,
            errno.EADDRNOTAVAIL,
            errno.ENODEV,
        }
        for code in (
            *sorted(unavailable),
            errno.EADDRINUSE,
            errno.EACCES,
            errno.EMFILE,
        ):

            def bind(
                listeners: LoopbackListeners, family: socket.AddressFamily, host: str
            ) -> None:
                if family == socket.AF_INET6:
                    raise OSError(code, "IPv6 bind failure")
                original(listeners, family, host)

            with (
                subtests.test(errno=code),
                patch.dict(os.environ, {}, clear=True),
                patch.object(
                    LoopbackListeners,
                    "_bind",
                    bind,
                ),
            ):
                if code in unavailable:
                    caplog.clear()
                    with caplog.at_level("WARNING", logger="azure_dev_proxy.listeners"):
                        with LoopbackListeners(0) as listeners:
                            assert [listener.family for listener in listeners] == [
                                socket.AF_INET
                            ]
                    assert any(
                        record.name == "azure_dev_proxy.listeners"
                        or record.name.startswith("azure_dev_proxy.listeners" + ".")
                        for record in caplog.records
                    )
                else:
                    with pytest.raises(OSError) as error:
                        with LoopbackListeners(0):
                            pytest.fail("Fatal IPv6 errors must prevent startup")
                    assert error.value.errno == code

    def test_ipv6_port_conflict_fails_and_releases_ipv4_listener(self) -> None:
        try:
            occupied = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError as error:
            if error.errno in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT}:
                pytest.skip("IPv6 is unavailable")
            raise
        with occupied, patch.dict(os.environ, {}, clear=True):
            occupied.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                occupied.bind(("::1", 0))
            except OSError as error:
                if error.errno in {errno.EADDRNOTAVAIL, errno.ENODEV}:
                    pytest.skip("IPv6 loopback is unavailable")
                raise
            occupied.listen(1)
            port = occupied.getsockname()[1]
            with pytest.raises(OSError) as error:
                with LoopbackListeners(port):
                    pytest.fail("Conflicting IPv6 listeners must prevent startup")
            assert error.value.errno == errno.EADDRINUSE
            with socket.socket() as ipv4:
                ipv4.bind(("127.0.0.1", port))


class TestActivation:
    @pytest.fixture(autouse=True)
    def configuration(self, tmp_path, request) -> None:
        self.request = request
        self.path = tmp_path / "config.json"
        self.path.write_text('{"token_rules":[]}', encoding="utf-8")

    def start(
        self, listener: socket.socket, *, port: int | None = None, count: int = 1
    ) -> subprocess.Popen[bytes]:
        bootstrap = (
            "import os,sys;"
            "os.dup2(int(sys.argv[1]),3);os.set_inheritable(3,True);"
            "os.environ['LISTEN_PID']=str(os.getpid());"
            "os.execv(sys.executable,[sys.executable,'-m','azure_dev_proxy',*sys.argv[2:]])"
        )
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                bootstrap,
                str(listener.fileno()),
                "--config",
                str(self.path),
                "--port",
                str(port or listener.getsockname()[1]),
                "--idle-timeout",
                "1",
                "--no-auth",
            ],
            pass_fds=(listener.fileno(),),
            env=os.environ | {"LISTEN_FDS": str(count)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.request.addfinalizer(partial(self.stop, process))
        return process

    @staticmethod
    def stop(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)

    def test_inherited_listener_idle_exit_restart_and_override_loss(
        self, request
    ) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
            port = listener.getsockname()[1]
            process = self.start(listener)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            request.addfinalizer(partial(connection.close))
            connection.request("GET", "/", headers={"Host": f"localhost:{port}"})
            response = connection.getresponse()
            assert response.status == 200
            page = response.read().decode()
            match = re.search(
                r'name="azure-dev-proxy-csrf" content="([a-f0-9]{64})"', page
            )
            assert match is not None
            csrf = match.group(1)
            connection.request(
                "POST",
                "/:config",
                json.dumps({"host": "temporary.example"}),
                {
                    "Host": f"localhost:{port}",
                    "Origin": f"http://localhost:{port}",
                    "Content-Type": "application/json",
                    "X-Azure-Proxy-CSRF": csrf,
                },
            )
            response = connection.getresponse()
            assert response.status == 200
            assert b"temporary.example" in response.read()
            assert process.wait(timeout=10) == 0
            connection.close()
            process = self.start(listener)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            request.addfinalizer(partial(connection.close))
            connection.request("GET", "/:config")
            data = json.loads(connection.getresponse().read())
            assert data["overrides"] == []
            assert json.loads(self.path.read_text())["token_rules"] == []

    def test_activation_rejects_public_listeners_wrong_ports_and_counts(
        self, subtests
    ) -> None:
        for address, wrong_port, count in [
            ("0.0.0.0", False, 1),
            ("127.0.0.1", True, 1),
            ("127.0.0.1", False, 3),
        ]:
            with (
                subtests.test(address=address, wrong_port=wrong_port, count=count),
                socket.socket() as listener,
            ):
                listener.bind((address, 0))
                listener.listen(128)
                port = listener.getsockname()[1]
                process = self.start(
                    listener, port=port - 1 if wrong_port else port, count=count
                )
                output, errors = process.communicate(timeout=5)
                assert process.returncode == 1, errors
                assert b"listening at" not in output
                assert b"Traceback" not in errors
