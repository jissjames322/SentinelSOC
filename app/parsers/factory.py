"""Parser Factory for SentinelSOC.

Provides a central registry of all available log parsers and a
convenience method to instantiate them by name.
"""

import logging
from typing import Dict, List, Type

from app.parsers.apache import ApacheParser
from app.parsers.base_parser import BaseParser
from app.parsers.cpanel import CPanelParser
from app.parsers.generic import GenericParser
from app.parsers.mis import MISParser
from app.parsers.nginx import NginxParser
from app.parsers.ssh import SSHParser

logger = logging.getLogger(__name__)


class ParserFactory:
    """Factory for creating log parser instances.

    Maintains a static registry that maps lowercase source names to
    their corresponding parser classes.  Use :meth:`get_parser` to
    obtain an instance and :meth:`available_parsers` to list registered
    source names.
    """

    _parsers: Dict[str, Type[BaseParser]] = {
        "mis": MISParser,
        "cpanel": CPanelParser,
        "apache": ApacheParser,
        "nginx": NginxParser,
        "ssh": SSHParser,
        "generic": GenericParser,
    }

    @staticmethod
    def get_parser(source: str) -> BaseParser:
        """Return a parser instance for the given source name.

        Args:
            source: Case-insensitive source identifier (e.g. ``'mis'``,
                ``'apache'``).

        Returns:
            An instance of the matching :class:`BaseParser` subclass.

        Raises:
            ValueError: If *source* does not match any registered parser.
        """
        source = source.lower().strip()
        parser_class = ParserFactory._parsers.get(source)

        if not parser_class:
            logger.error(
                "Unsupported parser requested: '%s'. Available: %s",
                source,
                list(ParserFactory._parsers.keys()),
            )
            raise ValueError(
                f"Unsupported parser: {source}. "
                f"Available: {list(ParserFactory._parsers.keys())}"
            )

        logger.debug("Instantiating parser for source '%s'", source)
        return parser_class()

    @staticmethod
    def available_parsers() -> List[str]:
        """Return a list of all registered parser source names.

        Returns:
            Sorted list of lowercase source identifiers.
        """
        return sorted(ParserFactory._parsers.keys())