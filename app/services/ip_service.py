import logging
import json
from app.extensions import db
from app.intelligence.engine import lookup
from app.repositories.ip_repository import IPRepository

logger = logging.getLogger(__name__)

class IPService:
    """Service to handle standalone IP lookup operations and intelligence caching."""

    def __init__(self):
        self.ip_repo = IPRepository()

    def lookup_and_store(self, ip_str: str) -> dict:
        """Runs intelligence lookup on an IP, stores or updates the results in the database, and returns the dict."""
        logger.info(f"Lookup and store requested for IP: {ip_str}")
        
        # 1. Lookup intelligence
        intel = lookup(ip_str)
        if "error" in intel and not intel.get("ip"):
            return intel

        # 2. Map fields to repository format
        ip_data = {
            "ip": intel["ip"],
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
            # 3. Store/Update IP address details
            ip_record = self.ip_repo.get_or_create(ip_data)
            db.session.commit()
            
            # Return updated dictionary representation
            return ip_record.to_dict()
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to save IP lookup for {ip_str}: {str(e)}")
            # Fallback to returning raw intelligence lookup results
            return intel

    def get_ip_details(self, ip_str: str) -> dict:
        """Gets stored IP intelligence and history, or performs lookup if not present."""
        record = self.ip_repo.get_by_ip(ip_str)
        if record:
            return record.to_dict()
        return self.lookup_and_store(ip_str)
