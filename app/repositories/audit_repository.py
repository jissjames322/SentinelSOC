"""Repository for audit log database operations.

All methods use db.session.flush() after mutations — commits are
handled at the service layer to allow proper transaction boundaries.
"""

import logging
from typing import Optional

from app.extensions import db
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AuditRepository:
    """Data-access layer for the audit_logs table."""

    @staticmethod
    def log_action(
        action: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        details: Optional[str] = None,
    ) -> AuditLog:
        """Record an administrative or system action in the audit log.

        Args:
            action: Short description of the action performed
                (e.g. 'IP_LOOKUP', 'ALERT_RESOLVED').
            entity_type: Optional type of the entity acted upon
                (e.g. 'IPAddress', 'Alert').
            entity_id: Optional primary key of the entity acted upon.
            details: Optional free-text details or JSON string.

        Returns:
            AuditLog: The newly created audit log entry.
        """
        logger.info(
            "Audit: action=%s entity_type=%s entity_id=%s",
            action, entity_type, entity_id,
        )
        entry = AuditLog(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
        )
        db.session.add(entry)
        db.session.flush()
        return entry

    @staticmethod
    def get_recent(limit: int = 50) -> list[AuditLog]:
        """Return the most recent audit log entries.

        Args:
            limit: Maximum number of entries to return (default 50).

        Returns:
            list[AuditLog]: Most recent entries, newest first.
        """
        return AuditLog.query.order_by(
            AuditLog.created_at.desc()
        ).limit(limit).all()
