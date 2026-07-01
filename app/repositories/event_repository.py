"""Repository for security event database operations.

All methods use db.session.flush() after mutations — commits are
handled at the service layer to allow proper transaction boundaries.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func

from app.extensions import db
from app.models.security_event import SecurityEvent

logger = logging.getLogger(__name__)


class EventRepository:
    """Data-access layer for the security_events table."""

    @staticmethod
    def create(
        ip_id: Optional[int],
        username: Optional[str],
        event_type: Optional[str],
        status: Optional[str],
        source: Optional[str],
        description: Optional[str] = None,
        raw_line: Optional[str] = None,
        event_timestamp: Optional[datetime] = None,
    ) -> SecurityEvent:
        """Create a new security event record.

        Args:
            ip_id: Foreign key to the ip_addresses table.
            username: Username associated with the event.
            event_type: Category of the event (e.g. 'LOGIN_FAILED').
            status: Outcome status (e.g. 'FAILURE', 'SUCCESS').
            source: Log source identifier (e.g. 'auth.log').
            description: Optional human-readable description.
            raw_line: Optional raw log line that generated the event.
            event_timestamp: Optional timestamp from the log itself.

        Returns:
            SecurityEvent: The newly created event record.
        """
        logger.info(
            "Creating security event: type=%s source=%s ip_id=%s",
            event_type, source, ip_id,
        )
        event = SecurityEvent(
            ip_id=ip_id,
            username=username,
            event_type=event_type,
            status=status,
            source=source,
            description=description,
            raw_line=raw_line,
            event_timestamp=event_timestamp,
        )
        db.session.add(event)
        db.session.flush()
        return event

    @staticmethod
    def get_recent(limit: int = 20) -> list[SecurityEvent]:
        """Return the most recent security events.

        Args:
            limit: Maximum number of events to return.

        Returns:
            list[SecurityEvent]: Most recent events, newest first.
        """
        return SecurityEvent.query.order_by(
            SecurityEvent.created_at.desc()
        ).limit(limit).all()

    @staticmethod
    def get_by_ip_id(ip_id: int) -> list[SecurityEvent]:
        """Return all security events for a given IP address.

        Args:
            ip_id: The primary key of the related IP address record.

        Returns:
            list[SecurityEvent]: Events linked to the IP, newest first.
        """
        return SecurityEvent.query.filter_by(
            ip_id=ip_id
        ).order_by(SecurityEvent.created_at.desc()).all()

    @staticmethod
    def get_stats() -> dict:
        """Compute aggregate statistics for security events.

        Returns:
            dict: Contains 'total', 'by_status', 'by_source', and 'by_type'
            breakdowns with counts.
        """
        total = (
            db.session.query(func.count(SecurityEvent.id)).scalar() or 0
        )

        by_status_rows = (
            db.session.query(
                SecurityEvent.status,
                func.count(SecurityEvent.id).label('count'),
            )
            .group_by(SecurityEvent.status)
            .all()
        )
        by_status = {
            row.status or 'UNKNOWN': row.count for row in by_status_rows
        }

        by_source_rows = (
            db.session.query(
                SecurityEvent.source,
                func.count(SecurityEvent.id).label('count'),
            )
            .group_by(SecurityEvent.source)
            .all()
        )
        by_source = {
            row.source or 'UNKNOWN': row.count for row in by_source_rows
        }

        by_type_rows = (
            db.session.query(
                SecurityEvent.event_type,
                func.count(SecurityEvent.id).label('count'),
            )
            .group_by(SecurityEvent.event_type)
            .all()
        )
        by_type = {
            row.event_type or 'UNKNOWN': row.count for row in by_type_rows
        }

        return {
            'total': total,
            'by_status': by_status,
            'by_source': by_source,
            'by_type': by_type,
        }

    @staticmethod
    def get_timeline(days: int = 30) -> list[dict]:
        """Return daily event counts for the last N days.

        Args:
            days: Number of days to look back (default 30).

        Returns:
            list[dict]: Each dict has 'date' (ISO string) and 'count'.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        date_col = func.date(SecurityEvent.created_at)

        rows = (
            db.session.query(
                date_col.label('date'),
                func.count(SecurityEvent.id).label('count'),
            )
            .filter(SecurityEvent.created_at >= cutoff)
            .group_by(date_col)
            .order_by(date_col)
            .all()
        )

        return [
            {'date': str(row.date), 'count': row.count}
            for row in rows
        ]

    @staticmethod
    def count() -> int:
        """Return the total number of security event records.

        Returns:
            int: Total count of events.
        """
        return db.session.query(func.count(SecurityEvent.id)).scalar() or 0

    @staticmethod
    def get_paginated(page: int = 1, per_page: int = 50):
        """Return a paginated list of security events.

        Args:
            page: Page number (1-indexed).
            per_page: Number of records per page.

        Returns:
            Pagination: A Flask-SQLAlchemy pagination object.
        """
        return SecurityEvent.query.order_by(
            SecurityEvent.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
