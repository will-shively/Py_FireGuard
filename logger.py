import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger():
    if not os.path.exists("logs"):
        os.makedirs("logs")

    logger = logging.getLogger("PyStateGuard")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        "logs/firewall.log",
        maxBytes=5_000_000,
        backupCount=3
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger