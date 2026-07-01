"""Apache Combined Log Format Parser for SentinelSOC.

Parses Apache HTTP server access logs in the standard combined format::

    IP - - [DATE] "METHOD PATH PROTO" STATUS_CODE SIZE

Example::

    192.168.1.1 - - [15/Jan/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 200 1234
"""

import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Pattern

from .base_parser import BaseParser

logger = logging.getLogger(__name__)


class ApacheParser(BaseParser):
    """Parser for Apache combined access logs.

    Extracts the client IP, timestamp, HTTP status code, and raw request
    line from each log entry.  HTTP status codes in the 2xx–3xx range
    are mapped to ``SUCCESS``; 4xx–5xx are mapped to ``FAILED``.
    """

    SOURCE = "APACHE"
    EVENT_TYPE = "ACCESS"

    # Combined Log Format regex:
    #   (\S+)                           — client IP
    #   \s+\S+\s+\S+                    — identd + auth user (typically "- -")
    #   \s+\[([^\]]+)\]                 — bracketed datetime
    #   \s+"([^"]*)"                    — request line
    #   \s+(\d{3})                      — HTTP status code
    #   \s+(\S+)                        — response size
    #   (?:\s+"([^"]*)")?              — optional referer
    #   (?:\s+"([^"]*)")?              — optional user-agent
    _LINE_PATTERN: Pattern[str] = re.compile(
        r'(\S+)'
        r'\s+\S+\s+\S+'
        r'\s+\[([^\]]+)\]'
        r'\s+"([^"]*)"'
        r'\s+(\d{3})'
        r'\s+(\S+)'
        r'(?:\s+"([^"]*)")?'
        r'(?:\s+"([^"]*)")?'
    )

    # Apache date format: 15/Jan/2024:10:30:45 +0000
    _DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    @staticmethod
    def _status_from_code(code: int) -> str:
        """Map an HTTP status code to SUCCESS or FAILED.

        Args:
            code: The HTTP numeric status code.

        Returns:
            ``'SUCCESS'`` for 2xx and 3xx; ``'FAILED'`` otherwise.
        """
        if 200 <= code <= 399:
            return "SUCCESS"
        return "FAILED"

    @classmethod
    def _parse_timestamp(cls, raw_ts: str) -> str:
        """Convert an Apache-format timestamp to ISO 8601.

        Args:
            raw_ts: Raw timestamp string, e.g. ``15/Jan/2024:10:30:45 +0000``.

        Returns:
            ISO 8601 formatted string, or the original string if parsing fails.
        """
        try:
            dt = datetime.strptime(raw_ts, cls._DATE_FORMAT)
            return dt.isoformat()
        except ValueError:
            logger.warning("Could not parse Apache timestamp: %s", raw_ts)
            return raw_ts

    def parse(self, filepath: str) -> List[Dict[str, str]]:
        """Parse an Apache combined log file.

        Args:
            filepath: Path to the Apache access log file.

        Returns:
            List of standardized event dictionaries.
        """
        events: List[Dict[str, str]] = []
        logger.info("Starting Apache log parsing: %s", filepath)

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for line_num, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()

                    if not line:
                        continue

                    match: Optional[re.Match[str]] = self._LINE_PATTERN.match(line)

                    if not match:
                        logger.warning(
                            "Skipping unrecognised line %d in %s: %s",
                            line_num,
                            filepath,
                            line[:120],
                        )
                        continue

                    ip_address = match.group(1)
                    raw_ts = match.group(2)
                    status_code_str = match.group(4)

                    timestamp = self._parse_timestamp(raw_ts)

                    try:
                        status_code = int(status_code_str)
                    except ValueError:
                        logger.warning(
                            "Invalid HTTP status code '%s' on line %d in %s",
                            status_code_str,
                            line_num,
                            filepath,
                        )
                        status_code = 500

                    status = self._status_from_code(status_code)

                    events.append(
                        {
                            "timestamp": timestamp,
                            "username": "-",
                            "ip": ip_address,
                            "status": status,
                            "event_type": self.EVENT_TYPE,
                            "source": self.SOURCE,
                            "raw_line": line,
                        }
                    )

        except FileNotFoundError:
            logger.error("Apache log file not found: %s", filepath)
            raise
        except PermissionError:
            logger.error("Permission denied reading Apache log file: %s", filepath)
            raise
        except Exception:
            logger.exception("Unexpected error parsing Apache log file: %s", filepath)
            raise

        logger.info(
            "Apache log parsing complete: %s — %d events extracted",
            filepath,
            len(events),
        )
        return events
