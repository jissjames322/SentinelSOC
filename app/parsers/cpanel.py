"""cPanel Login Log Parser for SentinelSOC.

Parses cPanel login logs with the bracketed format::

    [DATE TIME] USERNAME [IP] STATUS

Example::

    [2024-01-15 10:30:45] admin [192.168.1.1] SUCCESS
"""

import logging
import re
from typing import Dict, List, Optional, Pattern

from .base_parser import BaseParser

logger = logging.getLogger(__name__)


class CPanelParser(BaseParser):
    """Parser for cPanel login logs.

    Uses a regular expression to extract timestamp, username, IP, and
    status from lines in the ``[DATE TIME] USERNAME [IP] STATUS`` format.
    Lines that do not match the expected pattern are skipped with a warning.
    """

    SOURCE = "CPANEL"
    EVENT_TYPE = "LOGIN"

    # Pattern breakdown:
    #   \[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]  — bracketed timestamp
    #   \s+(\S+)                                        — username
    #   \s+\[(\d{1,3}(?:\.\d{1,3}){3})\]               — bracketed IPv4 address
    #   \s+(\S+)                                        — status
    _LINE_PATTERN: Pattern[str] = re.compile(
        r"\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]"
        r"\s+(\S+)"
        r"\s+\[([^\]]+)\]"
        r"\s+(\S+)"
    )

    def parse(self, filepath: str) -> List[Dict[str, str]]:
        """Parse a cPanel login log file.

        Args:
            filepath: Path to the cPanel log file.

        Returns:
            List of standardized event dictionaries.
        """
        events: List[Dict[str, str]] = []
        logger.info("Starting cPanel log parsing: %s", filepath)

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for line_num, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()

                    if not line:
                        continue

                    match: Optional[re.Match[str]] = self._LINE_PATTERN.search(line)

                    if not match:
                        logger.warning(
                            "Skipping unrecognised line %d in %s: %s",
                            line_num,
                            filepath,
                            line[:120],
                        )
                        continue

                    raw_ts, username, ip_address, status = match.groups()

                    # Convert "2024-01-15 10:30:45" → "2024-01-15T10:30:45"
                    timestamp = raw_ts.strip().replace(" ", "T")
                    status = status.upper()

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
            logger.error("cPanel log file not found: %s", filepath)
            raise
        except PermissionError:
            logger.error("Permission denied reading cPanel log file: %s", filepath)
            raise
        except Exception:
            logger.exception("Unexpected error parsing cPanel log file: %s", filepath)
            raise

        logger.info(
            "cPanel log parsing complete: %s — %d events extracted",
            filepath,
            len(events),
        )
        return events
