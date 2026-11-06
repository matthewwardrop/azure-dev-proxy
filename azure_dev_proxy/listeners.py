from __future__ import annotations

import errno
import ipaddress
import logging
import os
import socket
from contextlib import AbstractContextManager
from types import TracebackType

LOG = logging.getLogger(__name__)


class LoopbackListeners(AbstractContextManager[list[socket.socket]]):
    """
    Loopback TCP listeners for direct or systemd-activated proxy startup.

    When systemd supplies LISTEN_PID and LISTEN_FDS, the context adopts its
    listening sockets and checks their addresses and ports. Otherwise, it binds
    IPv4 loopback and IPv6 loopback when available. Direct binding is the normal
    startup mode on Windows and on Linux without a configured systemd socket.

    Exiting closes this process's sockets. A configured systemd socket unit can
    retain the listening endpoint; direct startup has no external listener.

    Args:
        port: Configured loopback TCP port, also required for inherited sockets.
            Zero selects a free port shared by directly bound IPv4 and IPv6.
    """

    def __init__(self, port: int) -> None:
        self._port = port
        self._sockets: list[socket.socket] = []

    def __enter__(self) -> list[socket.socket]:
        """Return the inherited or newly bound sockets owned by this context."""
        try:
            if "LISTEN_PID" in os.environ or "LISTEN_FDS" in os.environ:
                if int(os.environ.get("LISTEN_PID", "0")) != os.getpid():
                    raise ValueError("Invalid systemd activation PID")
                count = int(os.environ.get("LISTEN_FDS", "0"))
                if not 1 <= count <= 2:
                    raise ValueError("Systemd activation requires one or two listeners")
                for descriptor in range(3, 3 + count):
                    listener = socket.socket(fileno=descriptor)
                    self._sockets.append(listener)
                    if (
                        listener.family not in {socket.AF_INET, socket.AF_INET6}
                        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                        != socket.SOCK_STREAM
                        or not listener.getsockopt(
                            socket.SOL_SOCKET, socket.SO_ACCEPTCONN
                        )
                    ):
                        raise ValueError("Activation requires listening TCP sockets")
                    address = listener.getsockname()
                    if (
                        not ipaddress.ip_address(address[0]).is_loopback
                        or address[1] != self._port
                    ):
                        raise ValueError(
                            "Activation requires loopback listeners on the configured port"
                        )
                    listener.set_inheritable(False)
                    listener.setblocking(False)
            else:
                self._bind(socket.AF_INET, "127.0.0.1")
                try:
                    self._bind(socket.AF_INET6, "::1")
                except OSError as error:
                    if error.errno not in {
                        errno.EAFNOSUPPORT,
                        errno.EPROTONOSUPPORT,
                        errno.EADDRNOTAVAIL,
                        errno.ENODEV,
                    }:
                        raise
                    LOG.warning(
                        "IPv6 loopback unavailable; listening on IPv4 loopback only"
                    )
            return self._sockets
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _bind(self, family: socket.AddressFamily, host: str) -> None:
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind((host, self._port))
            self._port = listener.getsockname()[1]
            listener.setblocking(False)
        except BaseException:
            listener.close()
            raise
        self._sockets.append(listener)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for listener in self._sockets:
            listener.close()
        self._sockets.clear()
