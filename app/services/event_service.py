import logging
import json
from datetime import datetime, timezone
from app.extensions import db
from app.services.validators import validate_event
from app.intelligence.engine import lookup
from app.repositories.ip_repository import IPRepository
from app.repositories.event_repository import EventRepository
from app.services.alert_service import AlertService

logger = logging.getLogger(__name__)

class EventProcessor:
    """Orchestrates the ingestion, intelligence lookup, threat scoring, and alert generation for events."""

    def __init__(self):
        self.ip_repo = IPRepository()
        self.event_repo = EventRepository()
        self.alert_service = AlertService()

    def process(self, event: dict) -> dict:
        """
        Process a security event log entry through the ingestion pipeline:
        Validate -> Lookup Intelligence -> Calculate Risk -> Store IP -> Store Event -> Generate Alerts -> Commit.
        """
        # 1. Validate the event
        validate_event(event)
        
        ip_str = event["ip"]
        logger.info(f"Ingesting security event from IP: {ip_str}")

        # 2 & 3. Run IP intelligence and calculate risk (inside lookup)
        intel = lookup(ip_str)
        
        # Prepare IP model dictionary from intelligence results
        ip_data = {
            "ip": ip_str,
            "hostname": intel.get("hostname"),
            "country": intel.get("country"),
            "country_iso": intel.get("country_iso"),
            "state": intel.get("state"),
            "city": intel.get("city"),
            "latitude": intel.get("latitude"),
            "longitude": intel.get("longitude"),
            "timezone": intel.get("timezone"),
            "postal_code": intel.get("postal_code"),
            "asn": intel.get("asn"),
            "asn_description": intel.get("asn_description"),
            "network_name": intel.get("network_name"),
            "network_cidr": intel.get("network_cidr"),
            "org_name": intel.get("org_name"),
            "isp": intel.get("isp"),
            "is_tor": intel.get("is_tor", False),
            "is_vpn": intel.get("is_vpn", False),
            "is_hosting": intel.get("is_hosting", False),
            "is_proxy": intel.get("is_proxy", False),
            "risk_score": intel.get("risk_score", 0),
            "risk_level": intel.get("risk_level", "LOW"),
            "risk_factors": json.dumps(intel.get("risk_factors", []))
        }

        try:
            # 4. Store/Update IP record
            ip_record = self.ip_repo.get_or_create(ip_data)
            
            # Extract log timestamp
            event_timestamp = None
            if event.get("timestamp"):
                try:
                    event_timestamp = datetime.fromisoformat(event["timestamp"])
                except Exception:
                    pass
            if not event_timestamp:
                event_timestamp = datetime.now(timezone.utc)

            # 5. Store Event
            event_record = self.event_repo.create(
                ip_id=ip_record.id,
                username=event.get("username", "-"),
                event_type=event.get("event_type", "GENERIC"),
                status=event.get("status", "SUCCESS"),
                source=event.get("source", "GENERIC"),
                description=event.get("description") or f"Auth attempt by user '{event.get('username')}'",
                raw_line=event.get("raw_line", ""),
                event_timestamp=event_timestamp
            )
            
            # Flush so IDs are generated for alerts relationship
            db.session.flush()

            # 6. Generate Alerts
            alerts = self.alert_service.check(event, ip_record, event_record)

            # 7. Commit Database Transaction
            db.session.commit()
            logger.info(f"Pipeline complete for event from {ip_str}. Event ID: {event_record.id}. Generated {len(alerts)} alerts.")

            return {
                "event_id": event_record.id,
                "ip_id": ip_record.id,
                "risk_score": ip_record.risk_score,
                "alerts_triggered": len(alerts)
            }

        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to process event from {ip_str} in pipeline: {str(e)}")
            raise e