"""SSH Auth Log Parser for SentinelSOC.

Parses syslog-style SSH authentication entries produced by ``sshd``::

    Mon DD HH:MM:SS hostname sshd[PID]: Accepted password for USERNAME from IP port PORT proto

Example lines::

    Jan 15 10:30:45 server1 sshd[12345]: Accepted password for admin from 192.168.1.1 port 22 ssh2
    Jan 15 10:31:02 server1 sshd[12346]: Failed password for root from 10.0.0.5 port 22 ssh2
"""

import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Pattern

from .base_parser import BaseParser

logger = logging.getLogger(__name__)


class SSHParser(BaseParser):
    """Parser for SSH authentication log entries.

    Matches both ``Accepted`` and ``Failed`` password lines from
    ``/var/log/auth.log`` (or equivalent).  Lines that do not contain
    an sshd password authentication entry are silently skipped.
    """

    SOURCE = "SSH"
    EVENT_TYPE = "LOGIN"

    # Pattern breakdown:
    #   (\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})  — syslog timestamp (Jan 15 10:30:45)
    #   \s+\S+                                    — hostname
    #   \s+sshd\[\d+\]:                           — sshd[PID]:
    #   \s+(Accepted|Failed)\s+password\s+for     — outcome keyword
    #   \s+(\S+)                                   — username
    #   \s+from\s+(\S+)                            — source IP
    _LINE_PATTERN: Pattern[str] = re.compile(
        r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+\S+"
        r"\s+sshd\[\d+\]:"
        r"\s+(Accepted|Failed)\s+password\s+for"
        r"\s+(\S+)"
        r"\s+from\s+(\S+)"
    )

    # Syslog timestamp format (no year — we default to the current year)
    _SYSLOG_DATE_FORMAT = "%b %d %H:%M:%S"

    @classmethod
    def _parse_timestamp(cls, raw_ts: str) -> str:
        """Convert a syslog-style timestamp to ISO 8601.

        Syslog timestamps lack a year component.  The current year is
        assumed to keep conversion deterministic.

        Args:
            raw_ts: Raw syslog timestamp, e.g. ``Jan 15 10:30:45``.

        Returns:
            ISO 8601 formatted string, or the original string on failure.
        """
        try:
            dt = datetime.strptime(raw_ts, cls._SYSLOG_DATE_FORMAT)
            dt = dt.replace(year=datetime.now().year)
            return dt.isoformat()
        except ValueError:
            logger.warning("Could not parse syslog timestamp: %s", raw_ts)
            return raw_ts

    def parse(self, filepath: str) -> List[Dict[str, str]]:
        """Parse an SSH auth log file.

        Args:
            filepath: Path to the SSH / auth log file.

        Returns:
            List of standardized event dictionaries.
        """
        events: List[Dict[str, str]] = []
        logger.info("Starting SSH log parsing: %s", filepath)

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for line_num, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()

                    if not line:
                        continue

                    match: Optional[re.Match[str]] = self._LINE_PATTERN.search(line)

                    if not match:
                        # SSH auth logs contain many non-password lines;
                        # skip silently to avoid excessive noise.
                        continue

                    raw_ts = match.group(1)
                    outcome = match.group(2)
                    username = match.group(3)
                    ip_address = match.group(4)

                    timestamp = self._parse_timestamp(raw_ts)
                    status = "SUCCESS" if outcome == "Accepted" else "FAILED"

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
            logger.error("SSH log file not found: %s", filepath)
            raise
        except PermissionError:
            logger.error("Permission denied reading SSH log file: %s", filepath)
            raise
        except Exception:
            logger.exception("Unexpected error parsing SSH log file: %s", filepath)
            raise

        logger.info(
            "SSH log parsing complete: %s — %d events extracted",
            filepath,
            len(events),
        )
        return events
