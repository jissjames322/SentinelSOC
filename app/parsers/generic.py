"""Generic CSV Log Parser for SentinelSOC.

Parses CSV files that contain a header row with the expected columns:

    timestamp, username, ip, status, event_type

Missing columns are filled with empty strings.  The ``source`` field is
always set to ``'GENERIC'``.

Example CSV::

    timestamp,username,ip,status,event_type
    2024-01-15T10:30:45,admin,192.168.1.1,SUCCESS,LOGIN
    2024-01-15T10:31:02,root,10.0.0.5,FAILED,LOGIN
"""

import csv
import logging
from typing import Dict, List, Set

from .base_parser import BaseParser

logger = logging.getLogger(__name__)


class GenericParser(BaseParser):
    """Parser for generic CSV log files.

    Reads the first row as a header and maps each subsequent row to a
    standardized event dictionary.  Columns that are absent from the
    header default to empty strings, making the parser tolerant of
    partial schemas.
    """

    SOURCE = "GENERIC"
    EXPECTED_COLUMNS: Set[str] = {"timestamp", "username", "ip", "status", "event_type"}

    def parse(self, filepath: str) -> List[Dict[str, str]]:
        """Parse a generic CSV log file.

        Args:
            filepath: Path to the CSV log file.

        Returns:
            List of standardized event dictionaries.
        """
        events: List[Dict[str, str]] = []
        logger.info("Starting generic CSV log parsing: %s", filepath)

        try:
            with open(filepath, "r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)

                if reader.fieldnames is None:
                    logger.warning("CSV file has no header row: %s", filepath)
                    return events

                # Normalise header names to lowercase for resilient matching
                normalised_fields = [f.strip().lower() for f in reader.fieldnames]
                present_columns = self.EXPECTED_COLUMNS.intersection(normalised_fields)
                missing_columns = self.EXPECTED_COLUMNS - present_columns

                if missing_columns:
                    logger.warning(
                        "CSV %s is missing expected columns: %s — they will default to ''",
                        filepath,
                        ", ".join(sorted(missing_columns)),
                    )

                for row_num, row in enumerate(reader, start=2):
                    # Build a lowercase-keyed copy for resilient lookup
                    normalised_row: Dict[str, str] = {
                        k.strip().lower(): (v.strip() if v else "")
                        for k, v in row.items()
                        if k is not None
                    }

                    timestamp = normalised_row.get("timestamp", "")
                    username = normalised_row.get("username", "")
                    ip_address = normalised_row.get("ip", "")
                    status = normalised_row.get("status", "").upper()
                    event_type = normalised_row.get("event_type", "").upper()

                    if status and status not in ("SUCCESS", "FAILED"):
                        logger.warning(
                            "Unexpected status '%s' on row %d in %s, defaulting to FAILED",
                            status,
                            row_num,
                            filepath,
                        )
                        status = "FAILED"

                    # Reconstruct the raw CSV line for auditing
                    raw_line = ",".join(
                        (v if v else "") for v in row.values() if v is not None
                    )

                    events.append(
                        {
                            "timestamp": timestamp,
                            "username": username,
                            "ip": ip_address,
                            "status": status,
                            "event_type": event_type,
                            "source": self.SOURCE,
                            "raw_line": raw_line,
                        }
                    )

        except FileNotFoundError:
            logger.error("Generic CSV log file not found: %s", filepath)
            raise
        except PermissionError:
            logger.error(
                "Permission denied reading generic CSV log file: %s", filepath
            )
            raise
        except csv.Error as exc:
            logger.error("CSV parsing error in %s: %s", filepath, exc)
            raise
        except Exception:
            logger.exception(
                "Unexpected error parsing generic CSV log file: %s", filepath
            )
            raise

        logger.info(
            "Generic CSV log parsing complete: %s — %d events extracted",
            filepath,
            len(events),
        )
        return events
