"""Repository for IP address database operations.

All methods use db.session.flush() after mutations — commits are
handled at the service layer to allow proper transaction boundaries.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func

from app.extensions import db
from app.models.ip_address import IPAddress

logger = logging.getLogger(__name__)


class IPRepository:
    """Data-access layer for the ip_addresses table."""

    @staticmethod
    def get_or_create(ip_data: dict) -> IPAddress:
        """Find an IP record by address or create a new one.

        If the record already exists, its fields are updated from *ip_data*
        and the ``lookup_count`` is incremented.

        Args:
            ip_data: Dictionary of IP address attributes. Must contain 'ip'.

        Returns:
            IPAddress: The found-or-created IP address record.
        """
        ip_address = ip_data.get('ip', '')
        existing = IPAddress.query.filter_by(ip=ip_address).first()

        if existing:
            logger.debug("Updating existing IP record: %s", ip_address)
            existing.lookup_count = (existing.lookup_count or 0) + 1
            existing.last_seen = datetime.now(timezone.utc)

            # Update all mutable fields from ip_data
            updatable_fields = [
                'hostname', 'country', 'country_iso', 'state', 'city',
                'latitude', 'longitude', 'timezone', 'postal_code',
                'asn', 'asn_description', 'network_name', 'network_cidr',
                'org_name', 'isp',
                'is_tor', 'is_vpn', 'is_hosting', 'is_proxy',
                'risk_score', 'risk_level', 'risk_factors',
            ]
            for field in updatable_fields:
                if field in ip_data:
                    value = ip_data[field]
                    # Serialize risk_factors list to JSON string
                    if field == 'risk_factors' and isinstance(value, (list, dict)):
                        value = json.dumps(value)
                    setattr(existing, field, value)

            db.session.flush()
            return existing

        # Serialize risk_factors if provided as a list/dict
        if 'risk_factors' in ip_data and isinstance(
            ip_data['risk_factors'], (list, dict)
        ):
            ip_data['risk_factors'] = json.dumps(ip_data['risk_factors'])

        logger.info("Creating new IP record: %s", ip_address)
        new_ip = IPAddress(**ip_data)
        db.session.add(new_ip)
        db.session.flush()
        return new_ip

    @staticmethod
    def get_by_ip(ip: str) -> Optional[IPAddress]:
        """Look up a single IP address record by its address string.

        Args:
            ip: The IP address string (e.g. '192.168.1.1').

        Returns:
            IPAddress or None: The matching record, or None if not found.
        """
        return IPAddress.query.filter_by(ip=ip).first()

    @staticmethod
    def get_all(page: int = 1, per_page: int = 50):
        """Return a paginated list of all IP address records.

        Args:
            page: Page number (1-indexed).
            per_page: Number of records per page.

        Returns:
            Pagination: A Flask-SQLAlchemy pagination object.
        """
        return IPAddress.query.order_by(
            IPAddress.last_seen.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_high_risk(threshold: int = 70) -> list[IPAddress]:
        """Return all IP addresses with a risk score at or above the threshold.

        Args:
            threshold: Minimum risk_score to include (default 70).

        Returns:
            list[IPAddress]: IP records meeting the risk threshold.
        """
        return IPAddress.query.filter(
            IPAddress.risk_score >= threshold
        ).order_by(IPAddress.risk_score.desc()).all()

    @staticmethod
    def get_map_data() -> list[dict]:
        """Return lightweight location data for all IPs that have coordinates.

        Returns:
            list[dict]: Each dict contains ip, lat, lng, country,
            risk_score, and risk_level.
        """
        rows = IPAddress.query.filter(
            IPAddress.latitude.isnot(None),
            IPAddress.longitude.isnot(None),
        ).all()

        return [
            {
                'ip': row.ip,
                'lat': row.latitude,
                'lng': row.longitude,
                'country': row.country,
                'risk_score': row.risk_score,
                'risk_level': row.risk_level,
            }
            for row in rows
        ]

    @staticmethod
    def get_by_country(country: str) -> list[IPAddress]:
        """Return all IP addresses originating from a given country.

        Args:
            country: Country name to filter by.

        Returns:
            list[IPAddress]: Matching IP records.
        """
        return IPAddress.query.filter(
            func.lower(IPAddress.country) == country.lower()
        ).order_by(IPAddress.last_seen.desc()).all()

    @staticmethod
    def search(query: str) -> list[IPAddress]:
        """Search IP records across multiple text fields.

        Searches ip, hostname, country, city, and org_name using
        case-insensitive LIKE matching.

        Args:
            query: The search term.

        Returns:
            list[IPAddress]: Matching IP records (max 100).
        """
        like_pattern = f"%{query}%"
        return IPAddress.query.filter(
            db.or_(
                IPAddress.ip.ilike(like_pattern),
                IPAddress.hostname.ilike(like_pattern),
                IPAddress.country.ilike(like_pattern),
                IPAddress.city.ilike(like_pattern),
                IPAddress.org_name.ilike(like_pattern),
            )
        ).order_by(IPAddress.last_seen.desc()).limit(100).all()

    @staticmethod
    def get_country_stats() -> list[dict]:
        """Aggregate IP counts grouped by country.

        Returns:
            list[dict]: Each dict has 'country' and 'count', sorted
            by count descending.
        """
        results = (
            db.session.query(
                IPAddress.country,
                func.count(IPAddress.id).label('count'),
            )
            .filter(IPAddress.country.isnot(None))
            .group_by(IPAddress.country)
            .order_by(func.count(IPAddress.id).desc())
            .all()
        )
        return [
            {'country': row.country, 'count': row.count}
            for row in results
        ]

    @staticmethod
    def count() -> int:
        """Return the total number of IP address records.

        Returns:
            int: Total count of IP records.
        """
        return db.session.query(func.count(IPAddress.id)).scalar() or 0

    @staticmethod
    def get_recent(limit: int = 10) -> list[IPAddress]:
        """Return the most recently seen IP address records.

        Args:
            limit: Maximum number of records to return.

        Returns:
            list[IPAddress]: The most recent IP records.
        """
        return IPAddress.query.order_by(
            IPAddress.last_seen.desc()
        ).limit(limit).all()