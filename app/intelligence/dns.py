"""
SentinelSOC DNS Intelligence Module.

Provides reverse DNS lookup capabilities for IP addresses,
resolving hostnames and PTR records using the system DNS resolver.
"""

import logging
import socket
from typing import Any, Dict, List, Optional

logger: logging.Logger = logging.getLogger(__name__)


def _empty_result() -> Dict[str, Any]:
    """Return a result dictionary with all DNS fields set to ``None``.

    Returns:
        A dictionary with DNS fields initialized to empty/null values.
    """
    return {
        'hostname': None,
        'ptr_records': [],
    }


def lookup(ip: str) -> Dict[str, Any]:
    """Perform a reverse DNS lookup for an IP address.

    Uses ``socket.gethostbyaddr`` to resolve the IP to its hostname
    and associated aliases (PTR records). Returns empty values on
    failure rather than raising exceptions.

    Args:
        ip: The IP address to look up (IPv4 or IPv6 string).

    Returns:
        A dictionary containing:
            - ``hostname`` (str or None): Primary reverse hostname.
            - ``ptr_records`` (list of str): List of all reverse DNS
              names including the primary hostname and any aliases.
    """
    result: Dict[str, Any] = _empty_result()

    try:
        hostname: str
        aliases: List[str]
        addresses: List[str]
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        result['hostname'] = hostname

        # Build PTR records list: primary hostname + any aliases
        ptr_records: List[str] = [hostname]
        for alias in aliases:
            if alias and alias not in ptr_records:
                ptr_records.append(alias)
        result['ptr_records'] = ptr_records

        logger.debug(
            "DNS reverse lookup successful for %s: hostname=%s, ptr_count=%d",
            ip,
            hostname,
            len(ptr_records),
        )

    except socket.herror:
        logger.info("No reverse DNS record found for %s", ip)
    except socket.gaierror as exc:
        logger.warning(
            "DNS resolution error for %s: %s", ip, exc
        )
    except socket.timeout:
        logger.warning("DNS lookup timed out for %s", ip)
    except OSError as exc:
        logger.warning("OS error during DNS lookup for %s: %s", ip, exc)
    except Exception:
        logger.exception("Unexpected error during DNS lookup for %s", ip)

    return result
