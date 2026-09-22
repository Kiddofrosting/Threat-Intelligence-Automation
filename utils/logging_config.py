"""Central logging setup so every module logs consistently."""

import logging
import sys


def setup_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("tia")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)

    # Keep noisy third-party libraries quiet unless we're in verbose mode.
    if not verbose:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("scapy").setLevel(logging.ERROR)

    return logger
