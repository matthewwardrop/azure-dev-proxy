from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from .config import Config
from .proxy import Proxy


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535")
    return port


def main() -> None:
    """
    Run the loopback proxy or validate its configuration without listening.

    POSIX supports inherited systemd listeners; otherwise the service binds its
    own loopback sockets. Windows uses direct listeners and native signal handling.
    """
    parser = argparse.ArgumentParser(
        prog="azure-dev-proxy",
        description="Local HTTP(S) proxy with HTTPS-only Azure CLI tokens",
    )
    parser.add_argument("--version", action="version", version="azure-dev-proxy 0.1.0")
    parser.add_argument(
        "--port", type=port_number, default=8080, help="Loopback port (default: 8080)"
    )
    parser.add_argument(
        "--az-path",
        default="az",
        help="Azure CLI executable path (default: az on PATH)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="JSON configuration (default: the user's azure-dev-proxy/config.json)",
    )
    parser.add_argument(
        "--idle-timeout",
        type=idle_seconds,
        default=0,
        help="Opt-in idle shutdown seconds (default: 0, disabled)",
    )
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument(
        "--token", help="Proxy authentication key (or AZURE_DEV_PROXY_TOKEN)"
    )
    auth.add_argument(
        "--token-file",
        type=Path,
        help="Saved key file (default: auth-token beside the configuration)",
    )
    auth.add_argument(
        "--no-auth", action="store_true", help="Disable proxy authentication"
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and exit without listening",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        if not args.check_config and hasattr(os, "geteuid") and os.geteuid() == 0:
            raise ValueError("Run azure-dev-proxy as a non-root user")
        if args.check_config:
            Config.load(
                args.config if args.config is not None else Config.default_path()
            )
            return
        proxy = Proxy(
            config_path=args.config,
            az_path=args.az_path,
            token=args.token,
            token_file=args.token_file,
            no_auth=args.no_auth,
        )
        proxy.serve(args.port, idle_timeout=args.idle_timeout)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Could not start azure-dev-proxy: {error}\n")


def idle_seconds(value: str) -> int:
    """Parse nonnegative idle seconds; zero disables automatic shutdown."""
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Idle timeout must be an integer") from None
    if seconds < 0:
        raise argparse.ArgumentTypeError("Idle timeout must be nonnegative")
    return seconds


if __name__ == "__main__":
    main()
