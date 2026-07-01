"""
SentinelSOC Logging Configuration Module.

Provides centralized logging setup with rotating file handlers
and console output for the entire application.
"""

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(app) -> None:
    """Configure application-wide logging with file and console handlers.

    Sets up a RotatingFileHandler that writes to the configured log directory
    and a StreamHandler for console output. The file handler rotates at 10MB
    with up to 5 backup files retained.

    Args:
        app: The Flask application instance. Uses ``LOG_FOLDER`` from
            ``app.config`` to determine the log directory (defaults to ``logs``).
    """
    log_dir: str = app.config.get('LOG_FOLDER', 'logs')
    os.makedirs(log_dir, exist_ok=True)

    log_file: str = os.path.join(log_dir, 'sentinel.log')

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    file_handler = RotatingFileHandler(
        log_file, maxBytes=10_485_760, backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    app.logger.info('SentinelSOC logging initialized')
