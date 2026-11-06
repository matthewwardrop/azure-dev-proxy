from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import shutil
import signal
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

LOG = logging.getLogger(__name__)


class AcquisitionError(Exception):
    """Sanitized category of token acquisition failure."""


def cli_command(executable: str, resource: str, *, windows: bool) -> list[str]:
    arguments = [
        "account",
        "get-access-token",
        "--resource",
        resource,
        "--output",
        "json",
    ]
    if windows and executable.lower().endswith((".cmd", ".bat")):
        # cmd expands metacharacters even inside some quoted arguments.
        if any(c in executable for c in '"%!\r\n&|<>^') or not re.fullmatch(
            r"https://[a-zA-Z0-9.:\[\]-]+(?:/[a-zA-Z0-9._~/-]*)?", resource
        ):
            raise AcquisitionError("unsafe Windows launcher argument")
        command = f'"{executable}" account get-access-token --resource "{resource}" --output json'
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", command]
    return [executable, *arguments]


class AzureCLI:
    """
    An Azure CLI executable used for noninteractive token acquisition.

    Attributes:
        executable: CLI name on PATH or an explicit executable path.
        timeout: Maximum acquisition duration in seconds.
    """

    def __init__(self, executable: str = "az", timeout: float = 30) -> None:
        self.executable = executable
        self.timeout = timeout

    async def _stop(self, process: asyncio.subprocess.Process) -> None:
        if os.name == "nt":
            if process.returncode is None:
                killer = await asyncio.create_subprocess_exec(
                    "taskkill",
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.wait()
        else:
            # Descendants can retain the pipes after their CLI parent exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await process.communicate()

    async def acquire(self, resource: str) -> str:
        """Return token metadata for a resource, or raise a sanitized acquisition error."""
        executable = shutil.which(self.executable)
        if executable is None:
            raise AcquisitionError("Azure CLI executable not found")
        command = cli_command(executable, resource, windows=os.name == "nt")
        try:
            if os.name == "nt" and executable.lower().endswith((".cmd", ".bat")):
                # Only the strictly validated batch-launcher form uses cmd.
                process = await asyncio.create_subprocess_shell(
                    command[-1],
                    executable=command[0],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=os.name != "nt",
                )
        except OSError as error:
            raise AcquisitionError("Azure CLI could not start") from error
        try:
            output, _ = await asyncio.wait_for(process.communicate(), self.timeout)
        except TimeoutError as error:
            await self._stop(process)
            raise AcquisitionError("Azure CLI timed out") from error
        except asyncio.CancelledError:
            await self._stop(process)
            raise
        if process.returncode:
            raise AcquisitionError("Azure CLI returned an error")
        try:
            return output.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AcquisitionError("Azure CLI returned invalid text") from error


@dataclass
class CacheEntry:
    token: str | None
    expires: float


@dataclass(frozen=True)
class TokenResult:
    token: str | None
    source: Literal["acquired", "cached", "unavailable", "cooldown", "non-https"]


class TokenProvider:
    """
    A bounded, HTTPS-destination-isolated in-memory Azure token cache.

    At most four acquisitions run concurrently across all origin/resource pairs.
    Additional acquisitions wait; requests for the same pair share one acquisition.

    Attributes:
        refresh_margin: Seconds before expiry at which tokens stop being reused.
        cooldown: Seconds to suppress repeated failed acquisitions per key.
        capacity: Maximum number of cached origin/resource pairs.
        closed: Whether shutdown has disabled further acquisition.
    """

    def __init__(
        self,
        acquire: Callable[[str], Awaitable[str]],
        *,
        clock: Callable[[], float] = time.time,
        refresh_margin: float = 120,
        cooldown: float = 30,
        capacity: int = 128,
    ) -> None:
        if capacity < 1:
            raise ValueError("Token cache capacity must be positive")
        self.acquire = acquire
        self.clock = clock
        self.refresh_margin = refresh_margin
        self.cooldown = cooldown
        self.capacity = capacity
        self.entries: OrderedDict[tuple[str, str], CacheEntry] = OrderedDict()
        self.pending: dict[tuple[str, str], asyncio.Task[str | None]] = {}
        self._acquisitions = asyncio.Semaphore(4)
        self.closed = False

    async def get(self, origin: str, resource: str) -> str | None:
        """Return a token, or None for non-HTTPS origins or acquisition failure."""
        return (await self.get_with_status(origin, resource)).token

    async def get_with_status(self, origin: str, resource: str) -> TokenResult:
        """Return a token and its source; non-HTTPS destinations are always anonymous."""
        if self.closed:
            raise RuntimeError("Token provider is closed")
        if urlsplit(origin).scheme != "https":
            return TokenResult(None, "non-https")
        key = (origin, resource)
        entry = self.entries.get(key)
        if entry is not None and self.clock() < entry.expires:
            self.entries.move_to_end(key)
            return TokenResult(
                entry.token, "cached" if entry.token is not None else "cooldown"
            )
        task = self.pending.get(key)
        if task is None:
            task = asyncio.create_task(self._fetch(key))
            self.pending[key] = task
        token = await asyncio.shield(task)
        return TokenResult(token, "acquired" if token is not None else "unavailable")

    async def _fetch(self, key: tuple[str, str]) -> str | None:
        origin, resource = key
        try:
            try:
                async with self._acquisitions:
                    output = await self.acquire(resource)
                try:
                    metadata = json.loads(output)
                except (ValueError, TypeError) as error:
                    raise AcquisitionError("invalid token JSON") from error
                if not isinstance(metadata, dict):
                    raise AcquisitionError("invalid token metadata")
                token = metadata.get("accessToken")
                expires = metadata.get("expires_on")
                if (
                    not isinstance(token, str)
                    or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token)
                    or isinstance(expires, bool)
                    or not isinstance(expires, (str, int, float))
                ):
                    raise AcquisitionError("missing or invalid token fields")
                try:
                    usable_until = float(expires) - self.refresh_margin
                except (ValueError, OverflowError) as error:
                    raise AcquisitionError("invalid token expiry") from error
                if not math.isfinite(usable_until) or usable_until <= self.clock():
                    raise AcquisitionError("token is expired or too close to expiry")
                entry = CacheEntry(token, usable_until)
            except AcquisitionError as error:
                LOG.warning(
                    "Token unavailable for %s (%s); forwarding anonymously for %.0f seconds",
                    origin,
                    error,
                    self.cooldown,
                )
                entry = CacheEntry(None, self.clock() + self.cooldown)
            self.entries[key] = entry
            self.entries.move_to_end(key)
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)
            return entry.token
        finally:
            self.pending.pop(key, None)

    async def close(self) -> None:
        """Cancel owned acquisitions and discard all cached tokens."""
        self.closed = True
        tasks = list(self.pending.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.pending.clear()
        self.entries.clear()
