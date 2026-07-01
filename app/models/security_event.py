"""Security Event model for recording individual events from log sources."""

from datetime import datetime, timezone

from app.extensions import db


class SecurityEvent(db.Model):
    """Records individual security events from log sources."""

    __tablename__ = 'security_events'

    id = db.Column(db.Integer, primary_key=True)
    ip_id = db.Column(db.Integer, db.ForeignKey('ip_addresses.id'), index=True)
    username = db.Column(db.String(100), index=True)
    event_type = db.Column(db.String(100))
    status = db.Column(db.String(30))
    source = db.Column(db.String(100))
    description = db.Column(db.Text)
    raw_line = db.Column(db.Text)
    event_timestamp = db.Column(db.DateTime)  # timestamp from the log itself
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Serialize the security event to a dictionary.

        Returns:
            dict: Dictionary representation of the security event.
        """
        return {
            'id': self.id,
            'ip_id': self.ip_id,
            'ip': self.ip_ref.ip if self.ip_ref else None,
            'username': self.username,
            'event_type': self.event_type,
            'status': self.status,
            'source': self.source,
            'description': self.description,
            'event_timestamp': (
                self.event_timestamp.isoformat() if self.event_timestamp else None
            ),
            'created_at': (
                self.created_at.isoformat() if self.created_at else None
            ),
        }