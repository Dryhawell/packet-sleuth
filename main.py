"""PacketSleuth command entry point.

Phase 1 only checks that the project starts and that logging works.
Analysis commands are added in the CLI phase.
"""

from __future__ import annotations

from packetsleuth import __app_name__, __version__
from packetsleuth.utils.logger import configure_logging


def main() -> int:
    """Start PacketSleuth and report that the skeleton is ready.

    Returns:
        Process exit code. ``0`` means startup succeeded.
    """
    logger = configure_logging()
    logger.info("%s %s started", __app_name__, __version__)

    print(f"{__app_name__} — Network Traffic Analyzer")
    print(f"Version: {__version__}")
    print("Phase: 1 — project initialization")
    print()
    print("The application skeleton is ready.")
    print("Packet reading and analysis are not available in this phase.")

    logger.info("Startup check completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
