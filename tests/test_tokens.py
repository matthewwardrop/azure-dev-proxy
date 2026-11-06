import asyncio
import json
import os
import shutil
import signal
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from azure_dev_proxy.tokens import (
    AcquisitionError,
    AzureCLI,
    CacheEntry,
    TokenProvider,
    cli_command,
)


def metadata(token="test-token", expires=4600):
    return json.dumps({"accessToken": token, "expires_on": expires})


class TestToken:
    @pytest.fixture(autouse=True)
    async def token_provider(self):
        self.now = 1000.0
        self.acquire = AsyncMock(return_value=metadata())
        self.provider = TokenProvider(self.acquire, clock=lambda: self.now)

        try:
            yield
        finally:
            await self.provider.close()

    async def test_cache_isolates_domains_even_for_shared_audience(self):
        resource = "https://baz.example"
        self.acquire.side_effect = [metadata("token-a"), metadata("token-b")]
        assert await self.provider.get("https://foo.example", resource) == "token-a"
        assert await self.provider.get("https://bar.example", resource) == "token-b"
        assert await self.provider.get("https://foo.example", resource) == "token-a"
        assert self.acquire.await_count == 2

    async def test_non_https_destinations_never_acquire_or_return_cached_tokens(
        self, subtests
    ):
        resource = "https://shared.example"
        for origin in (
            "http://example.com",
            "HTTP://example.com:443",
            "ftp://example.com",
            "example.com",
        ):
            with subtests.test(origin=origin):
                assert await self.provider.get(origin, resource) is None
                self.provider.entries[(origin, resource)] = CacheEntry(
                    "cached-secret", 5000
                )
                result = await self.provider.get_with_status(origin, resource)
                assert result.token is None
                assert result.source == "non-https"
                assert await self.provider.get(origin, resource) is None
        self.acquire.assert_not_awaited()
        assert not self.provider.pending
        assert await self.provider.get("https://example.com", resource) == "test-token"
        self.acquire.assert_awaited_once_with(resource)

    async def test_resources_and_ports_are_separate(self):
        for origin, resource in (
            ("https://foo.example", "https://foo.example"),
            ("https://bar.example", "https://bar.example"),
            ("https://foo.example:444", "https://foo.example"),
            ("https://foo.example", "https://baz.example"),
        ):
            await self.provider.get(origin, resource)
        assert self.acquire.await_count == 4

    async def test_refresh_at_exact_margin(self):
        await self.provider.get("https://a", "https://a")
        self.now = 4479
        await self.provider.get("https://a", "https://a")
        assert self.acquire.await_count == 1
        self.now = 4480
        self.acquire.return_value = metadata("new-token", 8000)
        assert await self.provider.get("https://a", "https://a") == "new-token"
        assert self.acquire.await_count == 2

    async def test_failure_cooldown_is_domain_specific(self, caplog):
        self.acquire.side_effect = [
            AcquisitionError("no access"),
            metadata("b-token"),
            metadata("a-token"),
        ]
        caplog.clear()
        with caplog.at_level("WARNING", logger="azure_dev_proxy.tokens"):
            assert await self.provider.get("https://a", "https://shared") is None
        assert any(
            record.name == "azure_dev_proxy.tokens"
            or record.name.startswith("azure_dev_proxy.tokens" + ".")
            for record in caplog.records
        )
        assert "forwarding anonymously" in caplog.messages[0]
        assert await self.provider.get("https://a", "https://shared") is None
        assert await self.provider.get("https://b", "https://shared") == "b-token"
        self.now = 1030
        assert await self.provider.get("https://a", "https://shared") == "a-token"
        assert self.acquire.await_count == 3

    async def test_invalid_outputs_warn_without_disclosing_output(
        self, caplog, subtests
    ):
        for output in (
            "",
            "sensitive-not-json",
            "[]",
            "{}",
            metadata("", 5000),
            metadata("secret\ninjected", 5000),
            metadata(expires=1120),
            metadata(expires="NaN"),
            metadata(expires=True),
            metadata(expires=[]),
            metadata(expires="foo"),
            metadata(expires=10**400),
        ):
            self.acquire.return_value = output
            self.provider.entries.clear()
            caplog.clear()
            with (
                subtests.test(output=output),
                caplog.at_level("WARNING", logger="azure_dev_proxy.tokens"),
            ):
                assert await self.provider.get("https://a", "https://a") is None
            assert any(
                record.name == "azure_dev_proxy.tokens"
                or record.name.startswith("azure_dev_proxy.tokens" + ".")
                for record in caplog.records
            )
            assert "sensitive" not in caplog.text
            assert "secret" not in caplog.text

    async def test_concurrent_acquisition_and_cancellation(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def acquire(resource):
            started.set()
            await release.wait()
            return metadata()

        self.provider.acquire = acquire
        first = asyncio.create_task(self.provider.get("https://a", "https://a"))
        await started.wait()
        second = asyncio.create_task(self.provider.get("https://a", "https://a"))
        other = asyncio.create_task(self.provider.get("https://b", "https://b"))
        await asyncio.sleep(0)
        assert len(self.provider.pending) == 2
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        release.set()
        assert await second == "test-token"
        assert await other == "test-token"
        assert len(self.provider.entries) == 2
        assert not self.provider.pending

    async def test_acquisition_concurrency_is_bounded_across_distinct_keys(self):
        started = asyncio.Queue()
        release = asyncio.Queue()
        active = 0
        peak = 0

        async def acquire(resource):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            started.put_nowait(resource)
            try:
                await release.get()
                return metadata()
            finally:
                active -= 1

        self.provider.acquire = acquire
        self.provider.capacity = 1
        waiters = [
            asyncio.create_task(
                self.provider.get(f"https://host-{index}", f"https://resource-{index}")
            )
            for index in range(9)
        ]
        try:
            for _ in range(4):
                await asyncio.wait_for(started.get(), 1)
            await asyncio.sleep(0)
            assert active == 4
            assert peak == 4
            assert started.empty()
            assert len(self.provider.pending) == 9
            release.put_nowait(None)
            await asyncio.wait_for(started.get(), 1)
            assert active == 4
            assert started.empty()
            for _ in range(8):
                release.put_nowait(None)
            tokens = await asyncio.wait_for(asyncio.gather(*waiters), 2)
            assert tokens == ["test-token"] * 9
            assert peak == 4
            assert active == 0
            assert not self.provider.pending
        finally:
            await self.provider.close()
            await asyncio.gather(*waiters, return_exceptions=True)

    async def test_shutdown_cancels_active_and_queued_acquisitions(self):
        started = asyncio.Queue()

        async def acquire(resource):
            started.put_nowait(resource)
            await asyncio.Event().wait()
            return metadata()

        self.provider.acquire = acquire
        waiters = [
            asyncio.create_task(
                self.provider.get(f"https://host-{index}", "https://shared")
            )
            for index in range(6)
        ]
        try:
            for _ in range(4):
                await asyncio.wait_for(started.get(), 1)
            await self.provider.close()
            results = await asyncio.wait_for(
                asyncio.gather(*waiters, return_exceptions=True), 1
            )
            assert all(
                (isinstance(result, asyncio.CancelledError) for result in results)
            )
            assert started.empty()
            assert not self.provider.pending
            assert not self.provider.entries
        finally:
            await self.provider.close()
            await asyncio.gather(*waiters, return_exceptions=True)

    async def test_failed_acquisitions_release_concurrency_slots(self, caplog):
        self.acquire.side_effect = [AcquisitionError("no access")] * 4 + [metadata()]
        caplog.clear()
        with caplog.at_level("WARNING", logger="azure_dev_proxy.tokens"):
            results = await asyncio.wait_for(
                asyncio.gather(
                    *(
                        self.provider.get(f"https://host-{index}", "https://shared")
                        for index in range(5)
                    )
                ),
                1,
            )
        assert any(
            record.name == "azure_dev_proxy.tokens"
            or record.name.startswith("azure_dev_proxy.tokens" + ".")
            for record in caplog.records
        )
        assert results == [None, None, None, None, "test-token"]

    async def test_lru_capacity(self):
        self.provider.capacity = 2
        for host in ("a", "b", "a", "c"):
            await self.provider.get("https://" + host, "https://" + host)
        assert list(self.provider.entries) == [
            ("https://a", "https://a"),
            ("https://c", "https://c"),
        ]
        await self.provider.get("https://b", "https://b")
        assert self.acquire.await_count == 4

    async def test_shutdown_cancels_acquisition(self):
        async def acquire(resource):
            await asyncio.sleep(100)
            return metadata()

        self.provider.acquire = acquire
        waiter = asyncio.create_task(self.provider.get("https://a", "https://a"))
        await asyncio.sleep(0)
        await self.provider.close()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not self.provider.entries
        assert not self.provider.pending


class TestCLI:
    @pytest.mark.parametrize("running", [True, False])
    async def test_windows_cleanup_stops_only_running_processes(self, running):
        process = AsyncMock(pid=1234, returncode=None if running else 0)
        killer = AsyncMock()
        with (
            patch("azure_dev_proxy.tokens.os.name", "nt"),
            patch(
                "azure_dev_proxy.tokens.asyncio.create_subprocess_exec",
                return_value=killer,
            ) as start,
        ):
            await AzureCLI()._stop(process)
        if running:
            start.assert_awaited_once_with(
                "taskkill",
                "/PID",
                "1234",
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            killer.wait.assert_awaited_once()
        else:
            start.assert_not_awaited()
        process.communicate.assert_awaited_once()

    async def test_cleanup_tolerates_an_already_exited_process_group(self):
        process = AsyncMock(pid=1234)
        with (
            patch("azure_dev_proxy.tokens.os.name", "posix"),
            patch("azure_dev_proxy.tokens.os.killpg", side_effect=ProcessLookupError),
        ):
            await AzureCLI()._stop(process)
        process.communicate.assert_awaited_once()

    async def test_start_failure_is_sanitized(self):
        with (
            patch("azure_dev_proxy.tokens.shutil.which", return_value="foo"),
            patch(
                "azure_dev_proxy.tokens.asyncio.create_subprocess_exec",
                side_effect=OSError("private detail"),
            ),
            pytest.raises(AcquisitionError, match="^Azure CLI could not start$"),
        ):
            await AzureCLI().acquire("https://foo.example")

    async def test_cancelled_acquisition_stops_its_process(self):
        process = AsyncMock()
        process.communicate.side_effect = asyncio.CancelledError
        with (
            patch("azure_dev_proxy.tokens.shutil.which", return_value="foo"),
            patch(
                "azure_dev_proxy.tokens.asyncio.create_subprocess_exec",
                return_value=process,
            ),
            patch.object(AzureCLI, "_stop", new_callable=AsyncMock) as stop,
            pytest.raises(asyncio.CancelledError),
        ):
            await AzureCLI().acquire("https://foo.example")
        stop.assert_awaited_once_with(process)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX owned process groups")
    async def test_cleanup_kills_owned_group_after_cli_parent_exit(self):
        process = AsyncMock()
        process.pid = 1234
        process.returncode = 0
        with patch("azure_dev_proxy.tokens.os.killpg") as kill:
            await AzureCLI()._stop(process)
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        process.communicate.assert_awaited_once()

    def test_posix_and_windows_commands(self):
        command = cli_command(
            "/path with spaces/az", "https://foo.example", windows=False
        )
        assert command[0] == "/path with spaces/az"
        assert command[4] == "https://foo.example"
        command = cli_command(
            r"C:\Program Files\Azure\az.cmd", "https://foo.example", windows=True
        )
        assert command[1:4] == ["/d", "/s", "/c"]
        assert '"C:\\Program Files\\Azure\\az.cmd"' in command[4]
        assert '"https://foo.example"' in command[4]
        for resource in (
            "https://a/&evil",
            "https://a/%PATH%",
            "https://a/!x!",
            'https://a/"',
        ):
            with pytest.raises(AcquisitionError):
                cli_command("az.cmd", resource, windows=True)
        for path in ('bad"az.cmd', "bad%az.cmd", "bad&az.cmd"):
            with pytest.raises(AcquisitionError):
                cli_command(path, "https://a", windows=True)

    async def test_missing_cli(self):
        with pytest.raises(AcquisitionError, match="not found"):
            await AzureCLI("/nonexistent/azure/cli").acquire("https://a")

    @pytest.mark.skipif(os.name == "nt", reason="Native POSIX executable fixture")
    async def test_real_fake_cli_with_spaces(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / "fake az"
            shutil.copyfile(Path(__file__).with_name("fake_az.py"), executable)
            executable.chmod(0o755)
            result = json.loads(
                await AzureCLI(str(executable)).acquire("https://foo.example")
            )
            assert result["accessToken"] == "fake-foo.example"
            assert result["expires_on"] > 0
            with pytest.raises(AcquisitionError, match="timed out"):
                await AzureCLI(str(executable), timeout=0.1).acquire(
                    "https://timeout.test"
                )

    async def test_windows_batch_dispatch_uses_validated_shell_command(self):
        process = AsyncMock()
        process.returncode = 0
        process.communicate.return_value = (metadata().encode(), b"")
        path = r"C:\Program Files\Azure\az.cmd"
        with (
            patch("azure_dev_proxy.tokens.os.name", "nt"),
            patch(
                "azure_dev_proxy.tokens.shutil.which",
                return_value=path,
            ),
            patch(
                "azure_dev_proxy.tokens.asyncio.create_subprocess_shell",
                return_value=process,
            ) as shell,
            patch(
                "azure_dev_proxy.tokens.asyncio.create_subprocess_exec",
            ) as direct,
        ):
            await AzureCLI(path).acquire("https://foo.example")
            shell.assert_awaited_once_with(
                f'"{path}" account get-access-token --resource "https://foo.example" --output json',
                executable=os.environ.get("COMSPEC", "cmd.exe"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            direct.assert_not_called()
            with pytest.raises(AcquisitionError):
                await AzureCLI(path).acquire("https://a/&evil")
            assert shell.await_count == 1

    async def test_cli_nonzero_invalid_text_and_timeout(self):
        process = AsyncMock()
        process.pid = 1234
        process.returncode = 1
        process.communicate.return_value = (b"SECRET", b"SECRET")
        with (
            patch("azure_dev_proxy.tokens.shutil.which", return_value="az"),
            patch(
                "azure_dev_proxy.tokens.asyncio.create_subprocess_exec",
                return_value=process,
            ),
        ):
            with pytest.raises(AcquisitionError, match="returned an error"):
                await AzureCLI().acquire("https://a")
            process.returncode = 0
            process.communicate.return_value = (b"\xff", b"")
            with pytest.raises(AcquisitionError, match="invalid text"):
                await AzureCLI().acquire("https://a")
            process.communicate.side_effect = TimeoutError()
            with patch.object(AzureCLI, "_stop", new_callable=AsyncMock) as stop:
                with pytest.raises(AcquisitionError, match="timed out"):
                    await AzureCLI().acquire("https://a")
                stop.assert_awaited_once_with(process)


class TestProviderValidation:
    def test_capacity_must_be_positive(self):
        with pytest.raises(ValueError, match="capacity must be positive"):
            TokenProvider(AsyncMock(), capacity=0)

    async def test_closed_provider_rejects_even_non_https_requests(self):
        acquire = AsyncMock()
        provider = TokenProvider(acquire)
        await provider.close()
        with pytest.raises(RuntimeError, match="provider is closed"):
            await provider.get_with_status("http://foo.example", "https://foo.example")
        acquire.assert_not_awaited()
