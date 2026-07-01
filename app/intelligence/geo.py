"""
SentinelSOC GeoIP Intelligence Module.

Provides geographic location data for IP addresses using the MaxMind
GeoLite2-City database. Uses a lazy-loaded singleton reader to avoid
repeated file opens.
"""

import ipaddress
import logging
import os
import threading
from typing import Any, Dict, Optional

import geoip2.database
import geoip2.errors

logger: logging.Logger = logging.getLogger(__name__)

_reader: Optional[geoip2.database.Reader] = None
_reader_lock: threading.Lock = threading.Lock()

DEFAULT_DB_PATH: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'database',
    'GeoLite2-City.mmdb',
)


def _get_reader() -> Optional[geoip2.database.Reader]:
    """Return the singleton GeoIP2 database reader, creating it on first call.

    Uses a threading lock to ensure only one reader instance is created
    even under concurrent access.

    Returns:
        The GeoIP2 database reader, or ``None`` if the database file
        cannot be opened.
    """
    global _reader
    if _reader is not None:
        return _reader

    with _reader_lock:
        # Double-checked locking
        if _reader is not None:
            return _reader

        db_path: str = os.environ.get('GEOIP_DB_PATH', DEFAULT_DB_PATH)
        if not os.path.isfile(db_path):
            logger.error("GeoIP2 database not found at: %s", db_path)
            return None

        try:
            _reader = geoip2.database.Reader(db_path)
            logger.info("GeoIP2 database loaded from: %s", db_path)
        except Exception:
            logger.exception("Failed to open GeoIP2 database at: %s", db_path)
            return None

    return _reader


def _empty_result(ip: str) -> Dict[str, Any]:
    """Return a result dictionary with all geo fields set to ``None``.

    Args:
        ip: The IP address string to include in the result.

    Returns:
        A dictionary with geo fields initialized to ``None``.
    """
    return {
        'ip': ip,
        'country': None,
        'country_iso': None,
        'state': None,
        'city': None,
        'latitude': None,
        'longitude': None,
        'timezone': None,
        'postal_code': None,
        'accuracy_radius': None,
    }


def lookup(ip: str) -> Dict[str, Any]:
    """Look up geographic information for an IP address.

    Handles private/reserved IP addresses by returning an empty result
    without querying the database. All exceptions are caught and logged,
    returning partial data when possible.

    Args:
        ip: The IP address to look up (IPv4 or IPv6 string).

    Returns:
        A dictionary containing:
            - ``ip`` (str): The queried IP address.
            - ``country`` (str or None): Full country name.
            - ``country_iso`` (str or None): ISO 3166-1 alpha-2 country code.
            - ``state`` (str or None): State or subdivision name.
            - ``city`` (str or None): City name.
            - ``latitude`` (float or None): Latitude coordinate.
            - ``longitude`` (float or None): Longitude coordinate.
            - ``timezone`` (str or None): IANA timezone identifier.
            - ``postal_code`` (str or None): Postal or ZIP code.
            - ``accuracy_radius`` (int or None): Accuracy radius in kilometres.
    """
    result: Dict[str, Any] = _empty_result(ip)

    # Short-circuit for private/reserved addresses
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            logger.debug("Skipping GeoIP lookup for private/reserved IP: %s", ip)
            return result
    except ValueError:
        logger.warning("Invalid IP address supplied to geo lookup: %s", ip)
        return result

    reader = _get_reader()
    if reader is None:
        logger.warning("GeoIP2 reader unavailable; returning empty geo result for %s", ip)
        return result

    try:
        response = reader.city(ip)

        result['country'] = (
            response.country.name if response.country else None
        )
        result['country_iso'] = (
            response.country.iso_code if response.country else None
        )

        if response.subdivisions and len(response.subdivisions) > 0:
            result['state'] = response.subdivisions.most_specific.name
        else:
            result['state'] = None

        result['city'] = response.city.name if response.city else None
        result['latitude'] = (
            response.location.latitude if response.location else None
        )
        result['longitude'] = (
            response.location.longitude if response.location else None
        )
        result['timezone'] = (
            response.location.time_zone if response.location else None
        )
        result['postal_code'] = (
            response.postal.code if response.postal else None
        )
        result['accuracy_radius'] = (
            response.location.accuracy_radius if response.location else None
        )

        logger.debug(
            "GeoIP lookup successful for %s: %s, %s",
            ip,
            result['country'],
            result['city'],
        )

    except geoip2.errors.AddressNotFoundError:
        logger.info("IP address not found in GeoIP2 database: %s", ip)
    except Exception:
        logger.exception("Unexpected error during GeoIP lookup for %s", ip)

    return result
