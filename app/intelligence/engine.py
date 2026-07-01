"""
SentinelSOC Intelligence Engine – Unified Orchestrator.

Provides a single entry point ``lookup(ip)`` that validates the target IP,
dispatches lookups to every intelligence sub-module, and merges the results
into one flat dictionary.  Private/reserved IPs are short-circuited with
basic metadata only.  All exceptions are caught so that partial results
are always returned.
"""

import ipaddress
import logging
from typing import Any, Dict, List, Optional

from app.intelligence import dns, geo, rdap, tor, vpn, risk

logger: logging.Logger = logging.getLogger(__name__)


def lookup(ip: str) -> Dict[str, Any]:
    """Perform a comprehensive intelligence lookup for an IP address.

    Orchestration flow:
        1. Validate the IP address using the ``ipaddress`` module.
        2. Short-circuit private/reserved/loopback addresses with basic info.
        3. Run GeoIP, RDAP, and DNS lookups.
        4. Feed RDAP results into VPN/hosting detection.
        5. Run TOR exit-node detection.
        6. Calculate a composite risk score from all gathered data.
        7. Merge everything into a single flat dictionary.

    Any exception in a sub-module is caught and logged; the engine
    returns whatever partial data it has collected along with an
    ``error`` field describing the failure.

    Args:
        ip: The IP address to investigate (IPv4 or IPv6 string).

    Returns:
        A dictionary containing **all** fields from every sub-module,
        plus the following top-level keys:

        - ``ip`` (str): The queried IP address.
        - ``version`` (int): IP version (4 or 6).
        - ``is_private`` (bool): Whether the IP is private/reserved.
        - ``error`` (str or None): Error description, if any step failed.
    """
    result: Dict[str, Any] = {
        'ip': ip,
        'version': None,
        'is_private': False,
        'error': None,
    }

    errors: List[str] = []

    # ── Step 1: Validate IP ─────────────────────────────────────────────
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        logger.error("Invalid IP address: %s – %s", ip, exc)
        result['error'] = f'Invalid IP address: {ip}'
        return result

    result['version'] = addr.version
    result['is_private'] = addr.is_private or addr.is_reserved or addr.is_loopback

    # ── Step 2: Short-circuit private IPs ───────────────────────────────
    if result['is_private']:
        logger.info("Private/reserved IP detected; skipping external lookups: %s", ip)
        result.update({
            # Geo fields
            'country': None,
            'country_iso': None,
            'state': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'postal_code': None,
            'accuracy_radius': None,
            # RDAP fields
            'asn': None,
            'asn_description': None,
            'network_name': None,
            'network_cidr': None,
            'org_name': None,
            # DNS fields
            'hostname': None,
            'ptr_records': [],
            # VPN fields
            'is_vpn': False,
            'is_hosting': False,
            'is_proxy': False,
            'vpn_provider': None,
            'detection_method': 'none',
            # TOR fields
            'is_tor': False,
            'last_updated': None,
            # Risk fields
            'risk_score': 0,
            'risk_level': 'LOW',
            'risk_factors': [],
        })
        return result

    # ── Step 3: GeoIP Lookup ────────────────────────────────────────────
    geo_data: Dict[str, Any] = {}
    try:
        geo_data = geo.lookup(ip)
        logger.debug("GeoIP data collected for %s", ip)
    except Exception:
        logger.exception("GeoIP lookup failed for %s", ip)
        errors.append('GeoIP lookup failed')

    # ── Step 4: RDAP Lookup ─────────────────────────────────────────────
    rdap_data: Dict[str, Any] = {}
    try:
        rdap_data = rdap.lookup(ip)
        logger.debug("RDAP data collected for %s", ip)
    except Exception:
        logger.exception("RDAP lookup failed for %s", ip)
        errors.append('RDAP lookup failed')

    # ── Step 5: DNS Lookup ──────────────────────────────────────────────
    dns_data: Dict[str, Any] = {}
    try:
        dns_data = dns.lookup(ip)
        logger.debug("DNS data collected for %s", ip)
    except Exception:
        logger.exception("DNS lookup failed for %s", ip)
        errors.append('DNS lookup failed')

    # ── Step 6: VPN / Hosting Detection ─────────────────────────────────
    vpn_data: Dict[str, Any] = {}
    try:
        vpn_data = vpn.check(
            asn=rdap_data.get('asn'),
            asn_description=rdap_data.get('asn_description'),
            network_name=rdap_data.get('network_name'),
            org_name=rdap_data.get('org_name'),
        )
        logger.debug("VPN/hosting detection completed for %s", ip)
    except Exception:
        logger.exception("VPN/hosting detection failed for %s", ip)
        errors.append('VPN detection failed')

    # ── Step 7: TOR Detection ───────────────────────────────────────────
    tor_data: Dict[str, Any] = {}
    try:
        tor_data = tor.check(ip)
        logger.debug("TOR detection completed for %s", ip)
    except Exception:
        logger.exception("TOR detection failed for %s", ip)
        errors.append('TOR detection failed')

    # ── Step 8: Risk Scoring ────────────────────────────────────────────
    risk_data: Dict[str, Any] = {}
    try:
        risk_data = risk.calculate(
            is_tor=tor_data.get('is_tor', False),
            is_vpn=vpn_data.get('is_vpn', False),
            is_hosting=vpn_data.get('is_hosting', False),
            is_proxy=vpn_data.get('is_proxy', False),
            hostname=dns_data.get('hostname'),
            country_iso=geo_data.get('country_iso'),
        )
        logger.debug("Risk scoring completed for %s", ip)
    except Exception:
        logger.exception("Risk scoring failed for %s", ip)
        errors.append('Risk scoring failed')

    # ── Step 9: Merge All Results ───────────────────────────────────────
    # Order matters: later updates overwrite earlier ones, but 'ip' from
    # geo_data is identical so no conflict.
    result.update(geo_data)
    result.update(rdap_data)
    result.update(dns_data)
    result.update(vpn_data)
    result.update(tor_data)
    result.update(risk_data)

    # Ensure top-level keys are preserved after merge
    result['ip'] = ip
    result['version'] = addr.version
    result['is_private'] = False

    if errors:
        result['error'] = '; '.join(errors)
        logger.warning(
            "Intelligence lookup for %s completed with errors: %s",
            ip,
            result['error'],
        )
    else:
        logger.info(
            "Intelligence lookup for %s completed successfully "
            "(risk_score=%s, risk_level=%s)",
            ip,
            result.get('risk_score'),
            result.get('risk_level'),
        )

    return result
