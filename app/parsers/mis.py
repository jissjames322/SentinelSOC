"""MIS Login Log Parser for SentinelSOC.

Parses space-separated MIS login logs with the format::

    DATE TIME USERNAME STATUS IP

Example::

    2024-01-15 10:30:45 admin SUCCESS 192.168.1.1
"""

import logging
from typing import Dict, List

from .base_parser import BaseParser

logger = logging.getLogger(__name__)


class MISParser(BaseParser):
    """Parser for MIS (Management Information System) login logs.

    Each non-blank line is expected to contain at least five
    space-separated fields: date, time, username, status, and IP address.
    Lines with fewer fields are skipped with a warning.
    """

    SOURCE = "MIS"
    EVENT_TYPE = "LOGIN"
    MIN_FIELDS = 5

    def parse(self, filepath: str) -> List[Dict[str, str]]:
        """Parse an MIS login log file.

        Args:
            filepath: Path to the MIS log file.

        Returns:
            List of standardized event dictionaries.
        """
        events: List[Dict[str, str]] = []
        logger.info("Starting MIS log parsing: %s", filepath)

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for line_num, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()

                    if not line:
                        continue

                    parts = line.split()

                    if len(parts) < self.MIN_FIELDS:
                        logger.warning(
                            "Skipping malformed line %d in %s: insufficient fields (%d < %d)",
                            line_num,
                            filepath,
                            len(parts),
                            self.MIN_FIELDS,
                        )
                        continue

                    date_str = parts[0]
                    time_str = parts[1]
                    username = parts[2]
                    status = parts[3].upper()
                    ip_address = parts[4]

                    timestamp = f"{date_str}T{time_str}"

                    if status not in ("SUCCESS", "FAILED"):
                        logger.warning(
                            "Unexpected status '%s' on line %d in %s, defaulting to FAILED",
                            status,
                            line_num,
                            filepath,
                        )
                        status = "FAILED"

                    events.append(
                        {
                            "timestamp": timestamp,
                            "username": username,
                            "ip": ip_address,
                            "status": status,
                            "event_type": self.EVENT_TYPE,
                            "source": self.SOURCE,
                            "raw_line": line,
                        }
                    )

        except FileNotFoundError:
            logger.error("MIS log file not found: %s", filepath)
            raise
        except PermissionError:
            logger.error("Permission denied reading MIS log file: %s", filepath)
            raise
        except Exception:
            logger.exception("Unexpected error parsing MIS log file: %s", filepath)
            raise

        logger.info(
            "MIS log parsing complete: %s — %d events extracted", filepath, len(events)
        )
        return events