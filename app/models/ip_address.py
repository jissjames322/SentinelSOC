"""IP Address model for storing intelligence data per unique IP."""

import json
from datetime import datetime, timezone

from app.extensions import db


class IPAddress(db.Model):
    """Stores intelligence data for each unique IP address."""

    __tablename__ = 'ip_addresses'

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(255))

    # Geo
    country = db.Column(db.String(100))
    country_iso = db.Column(db.String(10))
    state = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timezone = db.Column(db.String(100))
    postal_code = db.Column(db.String(20))

    # Network
    asn = db.Column(db.String(50))
    asn_description = db.Column(db.String(255))
    network_name = db.Column(db.String(255))
    network_cidr = db.Column(db.String(50))
    org_name = db.Column(db.String(255))
    isp = db.Column(db.String(255))

    # Threat flags
    is_tor = db.Column(db.Boolean, default=False)
    is_vpn = db.Column(db.Boolean, default=False)
    is_hosting = db.Column(db.Boolean, default=False)
    is_proxy = db.Column(db.Boolean, default=False)

    # Risk
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='LOW')
    risk_factors = db.Column(db.Text)  # JSON string

    # Meta
    lookup_count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    events = db.relationship('SecurityEvent', backref='ip_ref', lazy='dynamic')
    alerts = db.relationship('Alert', backref='ip_ref', lazy='dynamic')

    def to_dict(self) -> dict:
        """Serialize the IP address record to a dictionary.

        Returns:
            dict: Dictionary representation of the IP address.
        """
        return {
            'id': self.id,
            'ip': self.ip,
            'hostname': self.hostname,
            'country': self.country,
            'country_iso': self.country_iso,
            'state': self.state,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'timezone': self.timezone,
            'postal_code': self.postal_code,
            'asn': self.asn,
            'asn_description': self.asn_description,
            'network_name': self.network_name,
            'network_cidr': self.network_cidr,
            'org_name': self.org_name,
            'isp': self.isp,
            'is_tor': self.is_tor,
            'is_vpn': self.is_vpn,
            'is_hosting': self.is_hosting,
            'is_proxy': self.is_proxy,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'risk_factors': json.loads(self.risk_factors) if self.risk_factors else [],
            'lookup_count': self.lookup_count,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }