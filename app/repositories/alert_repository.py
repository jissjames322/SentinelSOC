"""Repository for alert database operations.

All methods use db.session.flush() after mutations — commits are
handled at the service layer to allow proper transaction boundaries.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func

from app.extensions import db
from app.models.alert import Alert

logger = logging.getLogger(__name__)


class AlertRepository:
    """Data-access layer for the alerts table."""

    @staticmethod
    def create(
        severity: str,
        title: str,
        description: str,
        rule_name: str,
        ip_id: Optional[int] = None,
        event_id: Optional[int] = None,
    ) -> Alert:
        """Create a new alert record.

        Args:
            severity: Alert severity level (LOW, MEDIUM, HIGH, CRITICAL).
            title: Short summary of the alert.
            description: Detailed alert description.
            rule_name: Name of the rule that triggered the alert.
            ip_id: Optional foreign key to ip_addresses.
            event_id: Optional foreign key to security_events.

        Returns:
            Alert: The newly created alert record.
        """
        logger.info(
            "Creating alert: severity=%s rule=%s title=%s",
            severity, rule_name, title,
        )
        alert = Alert(
            severity=severity,
            title=title,
            description=description,
            rule_name=rule_name,
            ip_id=ip_id,
            event_id=event_id,
        )
        db.session.add(alert)
        db.session.flush()
        return alert

    @staticmethod
    def get_all(page: int = 1, per_page: int = 50):
        """Return a paginated list of all alerts.

        Args:
            page: Page number (1-indexed).
            per_page: Number of records per page.

        Returns:
            Pagination: A Flask-SQLAlchemy pagination object.
        """
        return Alert.query.order_by(
            Alert.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_unresolved() -> list[Alert]:
        """Return all alerts that have not been resolved.

        Returns:
            list[Alert]: Unresolved alerts, newest first.
        """
        return Alert.query.filter_by(
            resolved=False
        ).order_by(Alert.created_at.desc()).all()

    @staticmethod
    def resolve(alert_id: int) -> Optional[Alert]:
        """Mark an alert as resolved.

        Args:
            alert_id: The primary key of the alert to resolve.

        Returns:
            Alert or None: The updated alert, or None if not found.
        """
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            logger.warning("Alert not found for resolution: id=%s", alert_id)
            return None

        logger.info("Resolving alert: id=%s title=%s", alert_id, alert.title)
        alert.resolved = True
        alert.resolved_at = datetime.now(timezone.utc)
        db.session.flush()
        return alert

    @staticmethod
    def get_stats() -> dict:
        """Compute aggregate statistics for alerts.

        Returns:
            dict: Contains 'total', 'unresolved', 'by_severity', and
            'by_rule' breakdowns with counts.
        """
        total = db.session.query(func.count(Alert.id)).scalar() or 0

        unresolved = (
            db.session.query(func.count(Alert.id))
            .filter(Alert.resolved.is_(False))
            .scalar() or 0
        )

        by_severity_rows = (
            db.session.query(
                Alert.severity,
                func.count(Alert.id).label('count'),
            )
            .group_by(Alert.severity)
            .all()
        )
        by_severity = {
            row.severity or 'UNKNOWN': row.count for row in by_severity_rows
        }

        by_rule_rows = (
            db.session.query(
                Alert.rule_name,
                func.count(Alert.id).label('count'),
            )
            .group_by(Alert.rule_name)
            .all()
        )
        by_rule = {
            row.rule_name or 'UNKNOWN': row.count for row in by_rule_rows
        }

        return {
            'total': total,
            'unresolved': unresolved,
            'by_severity': by_severity,
            'by_rule': by_rule,
        }

    @staticmethod
    def count() -> int:
        """Return the total number of alert records.

        Returns:
            int: Total count of alerts.
        """
        return db.session.query(func.count(Alert.id)).scalar() or 0

    @staticmethod
    def count_unresolved() -> int:
        """Return the number of unresolved alerts.

        Returns:
            int: Count of unresolved alerts.
        """
        return (
            db.session.query(func.count(Alert.id))
            .filter(Alert.resolved.is_(False))
            .scalar() or 0
        )
