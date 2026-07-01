"""
SentinelSOC RDAP/WHOIS Intelligence Module.

Provides network registration and ASN information for IP addresses
using the RDAP protocol via the ipwhois library.
"""

import logging
from typing import Any, Dict, Optional

from ipwhois import IPWhois
from ipwhois.exceptions import (
    ASNRegistryError,
    HTTPLookupError,
    IPDefinedError,
    WhoisLookupError,
)

logger: logging.Logger = logging.getLogger(__name__)


def _empty_result() -> Dict[str, Any]:
    """Return a result dictionary with all RDAP fields set to ``None``.

    Returns:
        A dictionary with RDAP fields initialized to ``None``.
    """
    return {
        'asn': None,
        'asn_description': None,
        'network_name': None,
        'network_cidr': None,
        'org_name': None,
    }


def lookup(ip: str) -> Dict[str, Any]:
    """Perform an RDAP lookup for an IP address.

    Queries the RDAP registry at depth 1 to retrieve ASN, network, and
    organisation information. Falls back to an empty result on error.

    Args:
        ip: The IP address to look up (IPv4 or IPv6 string).

    Returns:
        A dictionary containing:
            - ``asn`` (str or None): Autonomous System Number.
            - ``asn_description`` (str or None): Human-readable ASN description.
            - ``network_name`` (str or None): Registered network name.
            - ``network_cidr`` (str or None): Network CIDR block.
            - ``org_name`` (str or None): Organisation name associated with the IP.
    """
    result: Dict[str, Any] = _empty_result()

    try:
        obj = IPWhois(ip)
        rdap_data: Dict[str, Any] = obj.lookup_rdap(depth=1)

        result['asn'] = rdap_data.get('asn')
        result['asn_description'] = rdap_data.get('asn_description')
        result['network_name'] = rdap_data.get('network', {}).get('name')
        result['network_cidr'] = rdap_data.get('network', {}).get('cidr')

        # Extract organisation name from the entities or top-level fields
        org_name: Optional[str] = None
        entities: Optional[Dict[str, Any]] = rdap_data.get('objects')
        if entities:
            for entity_key, entity_data in entities.items():
                contact = entity_data.get('contact', {})
                if contact and contact.get('name'):
                    org_name = contact['name']
                    break

        # Fallback to asn_description if no org found in entities
        if not org_name:
            org_name = rdap_data.get('asn_description')

        result['org_name'] = org_name

        logger.debug(
            "RDAP lookup successful for %s: ASN=%s, Org=%s",
            ip,
            result['asn'],
            result['org_name'],
        )

    except IPDefinedError:
        logger.info(
            "RDAP lookup skipped for private/defined IP: %s", ip
        )
    except (ASNRegistryError, HTTPLookupError, WhoisLookupError) as exc:
        logger.warning(
            "RDAP lookup failed for %s: %s: %s",
            ip,
            type(exc).__name__,
            exc,
        )
    except Exception:
        logger.exception("Unexpected error during RDAP lookup for %s", ip)

    return result
