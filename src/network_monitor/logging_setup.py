"""Logging configuration with rotating file handler and console output."""

from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(log_level: str = "INFO", log_dir: str = "logs") -> logging.Logger:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    logfile = log_path / "network_monitor.log"

    logger = logging.getLogger("network_monitor")
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s.%(module)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    rfh = RotatingFileHandler(
        logfile,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    rfh.setFormatter(formatter)
    rfh.setLevel(level)
    logger.addHandler(rfh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(level)
    logger.addHandler(ch)

    return logger
