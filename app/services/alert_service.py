import logging
from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models import Alert, SecurityEvent, IPAddress
from app.repositories.alert_repository import AlertRepository
from app.repositories.event_repository import EventRepository

logger = logging.getLogger(__name__)

class AlertService:
    """Service responsible for evaluating events and generating security alerts."""

    def __init__(self):
        self.alert_repo = AlertRepository()
        self.event_repo = EventRepository()

    def check(self, processed_event: dict, ip_record, event_record) -> list:
        """
        Evaluate a processed event and its associated intelligence against detection rules.
        Generates and stores alerts if rules match.
        """
        alerts_generated = []
        intel = processed_event.get("intelligence", {})
        ip = processed_event.get("ip")
        username = processed_event.get("username")
        status = processed_event.get("status")
        source = processed_event.get("source")

        # 1. TOR Exit Node detection
        if intel.get("is_tor"):
            alert = self.alert_repo.create(
                severity="CRITICAL",
                title="TOR Exit Node Detected",
                description=f"Security event from TOR exit node IP {ip} by user '{username}'.",
                rule_name="TOR_ACCESS",
                ip_id=ip_record.id if ip_record else None,
                event_id=event_record.id if event_record else None
            )
            alerts_generated.append(alert)
            logger.warning(f"Alert generated: TOR access from {ip}")

        # 2. VPN / Proxy detection
        elif intel.get("is_proxy") or intel.get("is_vpn"):
            alert = self.alert_repo.create(
                severity="MEDIUM",
                title="VPN/Proxy Access Detected",
                description=f"Security event from VPN/Proxy IP {ip} by user '{username}'. Provider: {intel.get('vpn_provider', 'Unknown')}",
                rule_name="VPN_PROXY_ACCESS",
                ip_id=ip_record.id if ip_record else None,
                event_id=event_record.id if event_record else None
            )
            alerts_generated.append(alert)
            logger.info(f"Alert generated: VPN/Proxy access from {ip}")

        # 3. Hosting / Cloud Provider detection
        if intel.get("is_hosting"):
            alert = self.alert_repo.create(
                severity="LOW",
                title="Hosting Provider IP Detected",
                description=f"Security event originating from hosting/datacenter IP {ip} by user '{username}'. Org: {intel.get('org_name', 'Unknown')}",
                rule_name="HOSTING_PROVIDER_ACCESS",
                ip_id=ip_record.id if ip_record else None,
                event_id=event_record.id if event_record else None
            )
            alerts_generated.append(alert)

        # 4. High Risk Score
        risk_score = intel.get("risk_score", 0)
        if risk_score >= 75:
            severity = "HIGH" if risk_score < 90 else "CRITICAL"
            alert = self.alert_repo.create(
                severity=severity,
                title="High Risk IP Activity",
                description=f"Security event from IP {ip} with high risk score ({risk_score}/100) by user '{username}'.",
                rule_name="HIGH_RISK_IP",
                ip_id=ip_record.id if ip_record else None,
                event_id=event_record.id if event_record else None
            )
            alerts_generated.append(alert)
            logger.warning(f"Alert generated: High risk IP activity from {ip} (score={risk_score})")

        # 5. Repeated Failed Logins (Brute Force)
        if status == "FAILED":
            # Check for failed logins from the same IP in the last 15 minutes
            fifteen_mins_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15)
            # Query recent failed events from the same IP
            recent_fails = SecurityEvent.query.filter(
                SecurityEvent.ip_id == ip_record.id,
                SecurityEvent.status == "FAILED",
                SecurityEvent.created_at >= fifteen_mins_ago
            ).count()

            if recent_fails >= 5:
                # Check if we already have an active alert for brute force from this IP in the last 15 minutes
                existing_alert = Alert.query.filter(
                    Alert.ip_id == ip_record.id,
                    Alert.rule_name == "BRUTE_FORCE_IP",
                    Alert.resolved == False,
                    Alert.created_at >= fifteen_mins_ago
                ).first()

                if not existing_alert:
                    alert = self.alert_repo.create(
                        severity="HIGH",
                        title="Brute Force Attempt Detected (IP)",
                        description=f"Multiple failed login attempts ({recent_fails}) detected from IP {ip} in the last 15 minutes.",
                        rule_name="BRUTE_FORCE_IP",
                        ip_id=ip_record.id if ip_record else None,
                        event_id=event_record.id if event_record else None
                    )
                    alerts_generated.append(alert)
                    logger.warning(f"Alert generated: Brute Force from IP {ip}")

            # Repeated Failed Logins (Credential Stuffing / Brute Force on same User)
            if username and username != "-":
                recent_user_fails = SecurityEvent.query.filter(
                    SecurityEvent.username == username,
                    SecurityEvent.status == "FAILED",
                    SecurityEvent.created_at >= fifteen_mins_ago
                ).count()

                if recent_user_fails >= 5:
                    existing_user_alert = Alert.query.filter(
                        Alert.rule_name == "CREDENTIAL_STUFFING_USER",
                        Alert.description.like(f"%'{username}'%"),
                        Alert.resolved == False,
                        Alert.created_at >= fifteen_mins_ago
                    ).first()

                    if not existing_user_alert:
                        alert = self.alert_repo.create(
                            severity="HIGH",
                            title="Repeated Failed Logins on User Account",
                            description=f"Multiple failed login attempts ({recent_user_fails}) on user '{username}' across different sources or IPs in the last 15 minutes.",
                            rule_name="CREDENTIAL_STUFFING_USER",
                            ip_id=ip_record.id if ip_record else None,
                            event_id=event_record.id if event_record else None
                        )
                        alerts_generated.append(alert)
                        logger.warning(f"Alert generated: Account Brute Force on user '{username}'")

        # 6. New Country Alert
        # If this user has previously logged in from other countries but not this one
        if username and username != "-" and status == "SUCCESS" and ip_record.country:
            previous_countries = db.session.query(IPAddress.country).join(SecurityEvent).filter(
                SecurityEvent.username == username,
                SecurityEvent.status == "SUCCESS",
                IPAddress.country != ip_record.country,
                IPAddress.country != None,
                IPAddress.country != "Unknown"
            ).distinct().all()

            # Clean list
            previous_country_names = [c[0] for c in previous_countries]
            
            if previous_country_names:
                # Check if the user has EVER logged in from this country before
                has_country_before = db.session.query(SecurityEvent).join(IPAddress).filter(
                    SecurityEvent.username == username,
                    SecurityEvent.status == "SUCCESS",
                    IPAddress.country == ip_record.country
                ).count()

                if has_country_before == 1: # Only this current event
                    alert = self.alert_repo.create(
                        severity="MEDIUM",
                        title="Login from New Country",
                        description=f"User '{username}' logged in successfully from {ip_record.country} ({ip}). Previous successful login countries: {', '.join(previous_country_names)}.",
                        rule_name="NEW_COUNTRY_LOGIN",
                        ip_id=ip_record.id if ip_record else None,
                        event_id=event_record.id if event_record else None
                    )
                    alerts_generated.append(alert)
                    logger.info(f"Alert generated: New country login for user '{username}' from {ip_record.country}")

        # 7. Impossible Travel
        if username and username != "-" and status == "SUCCESS" and ip_record.latitude and ip_record.longitude:
            # Get the previous successful event
            last_event = SecurityEvent.query.join(IPAddress).filter(
                SecurityEvent.username == username,
                SecurityEvent.status == "SUCCESS",
                SecurityEvent.id != event_record.id,
                IPAddress.latitude != None,
                IPAddress.longitude != None
            ).order_by(SecurityEvent.created_at.desc()).first()

            if last_event:
                # Calculate speed between last event and current event
                # Haversine formula
                import math
                lat1, lon1 = last_event.ip_ref.latitude, last_event.ip_ref.longitude
                lat2, lon2 = ip_record.latitude, ip_record.longitude
                
                # Check time difference (convert aware to naive to prevent timezone type errors)
                t1 = event_record.created_at.replace(tzinfo=None) if event_record.created_at.tzinfo else event_record.created_at
                t2 = last_event.created_at.replace(tzinfo=None) if last_event.created_at.tzinfo else last_event.created_at
                time_diff = (t1 - t2).total_seconds()
                
                if time_diff > 0 and time_diff < 14400:  # 4 hours
                    # Distance in km
                    R = 6371.0
                    dlat = math.radians(lat2 - lat1)
                    dlon = math.radians(lon2 - lon1)
                    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
                    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
                    distance = R * c

                    # Speed in km/h
                    speed = (distance / (time_diff / 3600.0))
                    
                    # Typical commercial jet is ~900 km/h. If speed > 1000 km/h, trigger Impossible Travel
                    if speed > 1000.0 and distance > 100:
                        alert = self.alert_repo.create(
                            severity="HIGH",
                            title="Impossible Travel Detected",
                            description=f"User '{username}' logged in from {ip_record.city or 'Unknown'}, {ip_record.country} ({ip}) and {last_event.ip_ref.city or 'Unknown'}, {last_event.ip_ref.country} within {round(time_diff / 60.0, 1)} minutes. Required travel speed: {round(speed, 1)} km/h.",
                            rule_name="IMPOSSIBLE_TRAVEL",
                            ip_id=ip_record.id if ip_record else None,
                            event_id=event_record.id if event_record else None
                        )
                        alerts_generated.append(alert)
                        logger.warning(f"Alert generated: Impossible travel for user '{username}': speed={speed} km/h")

        return alerts_generated