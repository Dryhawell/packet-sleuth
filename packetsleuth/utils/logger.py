"""Application logging for PacketSleuth.

Console output and an optional log file are configured here so every later
module can call ``logging.getLogger("packetsleuth.<module>")`` and inherit
the same format. This module does not read packets or contact the network.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_LOG_DIR = Path("logs")
DEFAULT_LOG_FILE = "packetsleuth.log"


def configure_logging(
    *,
    verbose: bool = False,
    quiet: bool = False,
    log_dir: Path | None = None,
) -> logging.Logger:
    """Attach console and file handlers to the ``packetsleuth`` logger.

    Args:
        verbose: When true, record DEBUG messages.
        quiet: When true, record WARNING and above. Ignored if ``verbose``
            is also true.
        log_dir: Directory for the log file. Defaults to ``logs/`` relative
            to the current working directory.

    Returns:
        The configured ``packetsleuth`` logger.

    The file handler is best-effort. If the directory cannot be created or
    the file cannot be opened, the process keeps running and a warning is
    written to the console.
    """
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logger = logging.getLogger("packetsleuth")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    target_dir = DEFAULT_LOG_DIR if log_dir is None else log_dir
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            target_dir / DEFAULT_LOG_FILE,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Log file could not be opened: %s", exc)

    return logger
