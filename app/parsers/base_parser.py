"""Base parser module for SentinelSOC log parsing framework."""

from abc import ABC, abstractmethod
from typing import Dict, List


class BaseParser(ABC):
    """Abstract base class for all log parsers.

    All concrete parser implementations must inherit from this class
    and implement the ``parse`` method.  Each parser is responsible for
    reading a specific log format and returning a list of standardized
    event dictionaries.

    Standardized event dictionary keys::

        {
            'timestamp':  str,  # ISO 8601 format or empty string
            'username':   str,  # username or empty string
            'ip':         str,  # IP address or empty string
            'status':     str,  # 'SUCCESS' or 'FAILED'
            'event_type': str,  # e.g. 'LOGIN', 'ACCESS'
            'source':     str,  # e.g. 'MIS', 'CPANEL', 'APACHE'
            'raw_line':   str,  # original log line
        }
    """

    @abstractmethod
    def parse(self, filepath: str) -> List[Dict[str, str]]:
        """Parse a log file and return standardized event dictionaries.

        Args:
            filepath: Absolute or relative path to the log file.

        Returns:
            A list of dictionaries, each representing one parsed event.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            PermissionError: If the file cannot be read.
        """
        pass