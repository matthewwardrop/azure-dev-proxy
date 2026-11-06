"""Shared interface for the local proxy's HTTP routers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from ..proxy import Proxy


class Router(ABC):
    """
    HTTP endpoints bound to one proxy instance.

    Attributes:
        proxy: Service supplying authentication, configuration and upstream I/O.
    """

    def __init__(self, proxy: Proxy) -> None:
        self.proxy = proxy

    @abstractmethod
    def register(self, app: web.Application) -> None:
        """Register this router's endpoints on an application."""

    @abstractmethod
    async def handle(self, request: web.Request) -> web.StreamResponse:
        """Handle a request after the proxy's cross-cutting policy checks."""
