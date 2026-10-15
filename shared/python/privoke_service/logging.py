"""Shared service logging defaults."""

from __future__ import annotations

import logging

LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"


def configure_logging(level: int = logging.INFO) -> None:
    """Configure predictable container logs at a service entry point."""
    logging.basicConfig(level=level, format=LOG_FORMAT, force=True)
