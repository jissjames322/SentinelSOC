"""Audit Log model for tracking administrative and system actions."""

from datetime import datetime, timezone

from app.extensions import db


class AuditLog(db.Model):
    """Tracks administrative and system actions for auditing."""

    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50))
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Serialize the audit log entry to a dictionary.

        Returns:
            dict: Dictionary representation of the audit log entry.
        """
        return {
            'id': self.id,
            'action': self.action,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'details': self.details,
            'created_at': (
                self.created_at.isoformat() if self.created_at else None
            ),
        }
