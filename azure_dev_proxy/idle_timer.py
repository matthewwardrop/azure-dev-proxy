from __future__ import annotations

import asyncio
import time
from collections.abc import Generator
from contextlib import contextmanager

from aiohttp import web


class IdleTracker:
    """
    Request activity and an optional idle-exit deadline for one proxy event loop.

    Requests remain active until their response or stream finishes or is
    cancelled. Waiting for an idle deadline is opt-in; the proxy service leaves
    it disabled by default. This tracker does not start or restart processes.
    """

    def __init__(self) -> None:
        self._active = 0
        self._idle_since = time.monotonic()
        self._changed = asyncio.Event()
        self._stopping = False

    @contextmanager
    def request(self) -> Generator[None]:
        """Keep the process active until a request finishes or is cancelled."""
        if self._stopping:
            raise web.HTTPServiceUnavailable(text="Proxy shutting down\n")
        self._active += 1
        self._changed.set()
        try:
            yield
        finally:
            self._active -= 1
            if not self._active:
                self._idle_since = time.monotonic()
            self._changed.set()

    async def wait_for_idle(self, timeout: float) -> None:
        """
        Wait for inactivity, then reject new requests so the service can exit.

        Args:
            timeout: Inactive seconds required after the last active request
                finishes. Open pages and unused keep-alive connections do not
                count as active requests.
        """
        while True:
            self._changed.clear()
            if self._active:
                await self._changed.wait()
                continue
            remaining = self._idle_since + timeout - time.monotonic()
            if remaining <= 0:
                self._stopping = True
                return
            try:
                await asyncio.wait_for(self._changed.wait(), remaining)
            except TimeoutError:
                pass
