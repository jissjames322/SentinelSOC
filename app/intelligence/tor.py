"""
SentinelSOC TOR Exit Node Detection Module.

Maintains an in-memory cache of known TOR exit node IP addresses,
refreshed from the Tor Project's bulk exit list with a 1-hour TTL.
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set

import requests

logger: logging.Logger = logging.getLogger(__name__)

TOR_EXIT_LIST_URL: str = 'https://check.torproject.org/torbulkexitlist'
CACHE_TTL_SECONDS: int = 3600  # 1 hour
REQUEST_TIMEOUT_SECONDS: int = 15

# ── Module-level Cache ──────────────────────────────────────────────────────
_exit_nodes: Set[str] = set()
_last_updated: Optional[float] = None
_cache_lock: threading.Lock = threading.Lock()


def _refresh_cache() -> None:
    """Fetch the TOR exit node list and update the module-level cache.

    Downloads the bulk exit list from the Tor Project. On network or
    parsing errors the cache is cleared to an empty set so that
    detection degrades gracefully (no false positives).
    """
    global _exit_nodes, _last_updated

    logger.info("Refreshing TOR exit node list from %s", TOR_EXIT_LIST_URL)

    try:
        response = requests.get(
            TOR_EXIT_LIST_URL,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

        nodes: Set[str] = set()
        for line in response.text.splitlines():
            stripped: str = line.strip()
            # Skip comments and blank lines
            if stripped and not stripped.startswith('#'):
                nodes.add(stripped)

        _exit_nodes = nodes
        _last_updated = time.time()

        logger.info(
            "TOR exit node cache refreshed: %d nodes loaded", len(nodes)
        )

    except requests.exceptions.Timeout:
        logger.warning(
            "Timeout while fetching TOR exit node list; using stale/empty cache"
        )
        if _last_updated is None:
            _exit_nodes = set()
    except requests.exceptions.ConnectionError:
        logger.warning(
            "Connection error while fetching TOR exit node list; "
            "using stale/empty cache"
        )
        if _last_updated is None:
            _exit_nodes = set()
    except requests.exceptions.HTTPError as exc:
        logger.warning(
            "HTTP error fetching TOR exit node list: %s; using stale/empty cache",
            exc,
        )
        if _last_updated is None:
            _exit_nodes = set()
    except Exception:
        logger.exception(
            "Unexpected error fetching TOR exit node list; using stale/empty cache"
        )
        if _last_updated is None:
            _exit_nodes = set()


def _ensure_cache() -> None:
    """Ensure the cache is populated and within the TTL window.

    Thread-safe: uses a lock so that only one thread performs a refresh
    at a time; other threads use the existing (possibly stale) cache.
    """
    global _last_updated

    needs_refresh: bool = (
        _last_updated is None
        or (time.time() - _last_updated) > CACHE_TTL_SECONDS
    )

    if not needs_refresh:
        return

    acquired: bool = _cache_lock.acquire(blocking=False)
    if not acquired:
        # Another thread is already refreshing; use existing cache
        logger.debug("TOR cache refresh already in progress; skipping")
        return

    try:
        # Double-check after acquiring lock
        if (
            _last_updated is not None
            and (time.time() - _last_updated) <= CACHE_TTL_SECONDS
        ):
            return
        _refresh_cache()
    finally:
        _cache_lock.release()


def check(ip: str) -> Dict[str, Any]:
    """Check whether an IP address is a known TOR exit node.

    Ensures the local cache is up to date before performing the lookup.
    If the cache cannot be refreshed (e.g. network unavailable), the
    check returns ``False`` to avoid false positives.

    Args:
        ip: The IP address to check (IPv4 or IPv6 string).

    Returns:
        A dictionary containing:
            - ``is_tor`` (bool): Whether the IP is a known TOR exit node.
            - ``last_updated`` (str or None): ISO 8601 timestamp of the
              last successful cache refresh, or ``None`` if never refreshed.
    """
    _ensure_cache()

    is_tor: bool = ip in _exit_nodes

    last_updated_str: Optional[str] = None
    if _last_updated is not None:
        last_updated_str = datetime.fromtimestamp(
            _last_updated, tz=timezone.utc
        ).isoformat()

    if is_tor:
        logger.info("TOR exit node detected: %s", ip)
    else:
        logger.debug("IP %s is not a known TOR exit node", ip)

    return {
        'is_tor': is_tor,
        'last_updated': last_updated_str,
    }
