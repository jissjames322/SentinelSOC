"""
SentinelSOC Risk Scoring Module.

Calculates a composite risk score (0–100) for an IP address based on
multiple threat indicators gathered by the intelligence modules.
"""

import logging
from typing import Any, Dict, FrozenSet, List, Tuple

logger: logging.Logger = logging.getLogger(__name__)

# ── Risk Factor Weights ─────────────────────────────────────────────────────
_FACTOR_TOR: int = 30
_FACTOR_VPN: int = 15
_FACTOR_HOSTING: int = 10
_FACTOR_PROXY: int = 20
_FACTOR_NO_PTR: int = 5
_FACTOR_HIGH_RISK_COUNTRY: int = 10

# ── High-Risk Country ISO Codes ─────────────────────────────────────────────
HIGH_RISK_COUNTRIES: FrozenSet[str] = frozenset({
    'CN',  # China
    'RU',  # Russia
    'KP',  # North Korea
    'IR',  # Iran
    'NG',  # Nigeria
    'RO',  # Romania
    'UA',  # Ukraine
    'BR',  # Brazil
    'VN',  # Vietnam
    'IN',  # India
    'PK',  # Pakistan
    'BD',  # Bangladesh
})

# ── Risk Level Thresholds ───────────────────────────────────────────────────
_THRESHOLDS: List[Tuple[int, str]] = [
    (75, 'CRITICAL'),
    (50, 'HIGH'),
    (25, 'MEDIUM'),
    (0, 'LOW'),
]


def _determine_level(score: int) -> str:
    """Map a numeric risk score to a human-readable risk level.

    Args:
        score: The risk score (0–100).

    Returns:
        One of ``'LOW'``, ``'MEDIUM'``, ``'HIGH'``, or ``'CRITICAL'``.
    """
    for threshold, level in _THRESHOLDS:
        if score >= threshold:
            return level
    return 'LOW'


def calculate(
    is_tor: bool = False,
    is_vpn: bool = False,
    is_hosting: bool = False,
    is_proxy: bool = False,
    hostname: Any = None,
    country_iso: Any = None,
) -> Dict[str, Any]:
    """Calculate a composite risk score for an IP address.

    Each positive indicator contributes a fixed weight to the total score,
    which is capped at 100. A list of human-readable risk factors is also
    returned for audit and display purposes.

    Args:
        is_tor: Whether the IP is a known TOR exit node.
        is_vpn: Whether the IP is associated with a VPN service.
        is_hosting: Whether the IP is on hosting/cloud infrastructure.
        is_proxy: Whether the IP is a known proxy.
        hostname: Reverse DNS hostname (``None`` means no PTR record).
        country_iso: ISO 3166-1 alpha-2 country code.

    Returns:
        A dictionary containing:
            - ``risk_score`` (int): Composite score in the range 0–100.
            - ``risk_level`` (str): ``'LOW'``, ``'MEDIUM'``, ``'HIGH'``,
              or ``'CRITICAL'``.
            - ``risk_factors`` (list of str): Descriptions of each factor
              that contributed to the score.
    """
    score: int = 0
    factors: List[str] = []

    # ── Evaluate Each Factor ────────────────────────────────────────────
    if is_tor:
        score += _FACTOR_TOR
        factors.append(f'TOR exit node detected (+{_FACTOR_TOR})')

    if is_vpn:
        score += _FACTOR_VPN
        factors.append(f'VPN service detected (+{_FACTOR_VPN})')

    if is_hosting:
        score += _FACTOR_HOSTING
        factors.append(f'Hosting/cloud provider detected (+{_FACTOR_HOSTING})')

    if is_proxy:
        score += _FACTOR_PROXY
        factors.append(f'Proxy service detected (+{_FACTOR_PROXY})')

    if not hostname:
        score += _FACTOR_NO_PTR
        factors.append(f'No PTR/reverse DNS record (+{_FACTOR_NO_PTR})')

    if country_iso and str(country_iso).upper() in HIGH_RISK_COUNTRIES:
        score += _FACTOR_HIGH_RISK_COUNTRY
        factors.append(
            f'High-risk country: {str(country_iso).upper()} '
            f'(+{_FACTOR_HIGH_RISK_COUNTRY})'
        )

    # ── Clamp and Classify ──────────────────────────────────────────────
    score = min(score, 100)
    level: str = _determine_level(score)

    logger.info(
        "Risk assessment: score=%d, level=%s, factors=%d",
        score,
        level,
        len(factors),
    )
    logger.debug("Risk factors: %s", factors)

    return {
        'risk_score': score,
        'risk_level': level,
        'risk_factors': factors,
    }
