"""
SentinelSOC VPN / Proxy / Hosting Detection Module.

Identifies whether an IP address belongs to a known VPN provider,
proxy service, or hosting/cloud infrastructure by matching ASN numbers
and scanning network/organisation names for telltale keywords.
"""

import logging
from typing import Any, Dict, FrozenSet, Optional, Set, Tuple

logger: logging.Logger = logging.getLogger(__name__)

# ── Known VPN / Hosting ASN Registry ────────────────────────────────────────
# Each entry maps an ASN (string, without the "AS" prefix) to a tuple of
# (provider_name, category) where category is one of: 'vpn', 'hosting', 'cloud'.

_KNOWN_ASNS: Dict[str, Tuple[str, str]] = {
    # Cloud / Hosting Providers
    '13335': ('Cloudflare', 'hosting'),
    '16509': ('Amazon', 'cloud'),
    '14061': ('DigitalOcean', 'hosting'),
    '63949': ('Linode (Akamai)', 'hosting'),
    '20473': ('Vultr', 'hosting'),
    '14618': ('Amazon Web Services', 'cloud'),
    '8075': ('Microsoft Azure', 'cloud'),
    '15169': ('Google', 'cloud'),
    '396982': ('Google Cloud', 'cloud'),
    '36351': ('SoftLayer (IBM)', 'hosting'),
    '24940': ('Hetzner', 'hosting'),
    '16276': ('OVH', 'hosting'),
    '46606': ('Unified Layer', 'hosting'),
    '393406': ('DigitalOcean', 'hosting'),
    '132203': ('Tencent Cloud', 'cloud'),
    '45102': ('Alibaba Cloud', 'cloud'),
    '137718': ('Alibaba Cloud', 'cloud'),
    '20860': ('IoMart', 'hosting'),
    # VPN / Anonymisation Providers
    '13768': ('NordVPN / PeerCraft', 'vpn'),
    '9009': ('M247 (VPN infrastructure)', 'vpn'),
    '207137': ('Surfshark', 'vpn'),
}

# Keywords that indicate VPN, proxy, or hosting in network/org names
_VPN_KEYWORDS: FrozenSet[str] = frozenset({
    'vpn',
    'proxy',
})

_HOSTING_KEYWORDS: FrozenSet[str] = frozenset({
    'hosting',
    'cloud',
    'datacenter',
    'data center',
    'server',
    'colo',
    'colocation',
})


def _normalise_asn(asn: Any) -> Optional[str]:
    """Normalise an ASN value to a plain numeric string.

    Handles inputs like ``'AS13335'``, ``'13335'``, or ``13335``.

    Args:
        asn: Raw ASN value from upstream data.

    Returns:
        The numeric ASN string, or ``None`` if the input is empty/invalid.
    """
    if asn is None:
        return None
    asn_str: str = str(asn).strip().upper()
    if asn_str.startswith('AS'):
        asn_str = asn_str[2:]
    return asn_str if asn_str else None


def _check_keywords(text: str) -> Tuple[bool, bool, bool]:
    """Scan a text string for VPN, proxy, and hosting keywords.

    Args:
        text: The string to scan (typically a network or org name).

    Returns:
        A tuple ``(is_vpn, is_hosting, is_proxy)`` indicating which
        categories were detected.
    """
    lower: str = text.lower()
    is_vpn: bool = any(kw in lower for kw in _VPN_KEYWORDS)
    is_hosting: bool = any(kw in lower for kw in _HOSTING_KEYWORDS)
    is_proxy: bool = 'proxy' in lower
    return is_vpn, is_hosting, is_proxy


def check(
    asn: Any = None,
    asn_description: Optional[str] = None,
    network_name: Optional[str] = None,
    org_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Determine if an IP is associated with a VPN, proxy, or hosting provider.

    Uses a two-phase detection strategy:
      1. **ASN matching** – checks the ASN against a curated registry of
         known VPN/hosting providers.
      2. **Keyword scanning** – scans the ASN description, network name,
         and organisation name for telltale keywords.

    Args:
        asn: The Autonomous System Number (e.g. ``'13335'`` or ``'AS13335'``).
        asn_description: Human-readable ASN description from RDAP.
        network_name: Registered network name from RDAP.
        org_name: Organisation name from RDAP.

    Returns:
        A dictionary containing:
            - ``is_vpn`` (bool): Whether the IP is likely a VPN exit node.
            - ``is_hosting`` (bool): Whether the IP is on hosting/cloud infra.
            - ``is_proxy`` (bool): Whether the IP is a known proxy.
            - ``vpn_provider`` (str or None): Name of the matched provider.
            - ``detection_method`` (str): How the detection was made, or
              ``'none'`` if nothing was detected.
    """
    result: Dict[str, Any] = {
        'is_vpn': False,
        'is_hosting': False,
        'is_proxy': False,
        'vpn_provider': None,
        'detection_method': 'none',
    }

    detection_methods: list = []

    # ── Phase 1: ASN Registry Match ─────────────────────────────────────
    normalised_asn: Optional[str] = _normalise_asn(asn)
    if normalised_asn and normalised_asn in _KNOWN_ASNS:
        provider_name, category = _KNOWN_ASNS[normalised_asn]
        result['vpn_provider'] = provider_name

        if category == 'vpn':
            result['is_vpn'] = True
        elif category in ('hosting', 'cloud'):
            result['is_hosting'] = True

        detection_methods.append(f'asn_match(AS{normalised_asn})')
        logger.debug(
            "ASN match: AS%s -> %s (%s)", normalised_asn, provider_name, category
        )

    # ── Phase 2: Keyword Scanning ───────────────────────────────────────
    texts_to_scan: list = [
        ('asn_description', asn_description),
        ('network_name', network_name),
        ('org_name', org_name),
    ]

    for field_name, text in texts_to_scan:
        if not text:
            continue

        kw_vpn, kw_hosting, kw_proxy = _check_keywords(text)

        if kw_vpn:
            result['is_vpn'] = True
            detection_methods.append(f'keyword_vpn({field_name})')
            logger.debug("VPN keyword detected in %s: %s", field_name, text)

        if kw_hosting:
            result['is_hosting'] = True
            detection_methods.append(f'keyword_hosting({field_name})')
            logger.debug("Hosting keyword detected in %s: %s", field_name, text)

        if kw_proxy:
            result['is_proxy'] = True
            detection_methods.append(f'keyword_proxy({field_name})')
            logger.debug("Proxy keyword detected in %s: %s", field_name, text)

    # ── Finalise Detection Method ───────────────────────────────────────
    if detection_methods:
        result['detection_method'] = '; '.join(detection_methods)
    else:
        logger.debug("No VPN/proxy/hosting indicators found for ASN=%s", asn)

    return result
