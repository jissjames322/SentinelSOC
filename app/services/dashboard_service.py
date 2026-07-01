import logging
from datetime import datetime, timedelta, timezone
from app.repositories.ip_repository import IPRepository
from app.repositories.event_repository import EventRepository
from app.repositories.alert_repository import AlertRepository

logger = logging.getLogger(__name__)

class DashboardService:
    """Service to aggregate dashboard statistics and summaries from repositories."""

    def __init__(self):
        self.ip_repo = IPRepository()
        self.event_repo = EventRepository()
        self.alert_repo = AlertRepository()

    def get_dashboard_data(self) -> dict:
        """Collect all required statistics for the main dashboard view."""
        try:
            total_events = self.event_repo.count()
            total_alerts = self.alert_repo.count_unresolved()
            total_ips = self.ip_repo.count()
            total_countries = len(self.ip_repo.get_country_stats())
            
            # High risk IPs count (risk score >= 70)
            high_risk_ips = len(self.ip_repo.get_high_risk(threshold=70))
            
            # Recent events
            recent_events_raw = self.event_repo.get_recent(limit=10)
            recent_events = [e.to_dict() for e in recent_events_raw]

            # Timeline data (last 30 days)
            timeline = self.event_repo.get_timeline(days=30)

            # Top countries
            top_countries = self.ip_repo.get_country_stats()[:10]

            # Risk distribution counts
            all_ips = self.ip_repo.search("")  # Search all
            risk_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            for ip in all_ips:
                lvl = (ip.risk_level or "LOW").lower()
                if lvl in risk_dist:
                    risk_dist[lvl] += 1
                else:
                    risk_dist["low"] += 1

            # Map data
            map_data = self.ip_repo.get_map_data()

            # Event stats summary by source/status
            event_stats = self.event_repo.get_stats()

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "total_ips": total_ips,
                "total_countries": total_countries,
                "high_risk_ips": high_risk_ips,
                "recent_events": recent_events,
                "timeline": timeline,
                "top_countries": top_countries,
                "risk_distribution": risk_dist,
                "map_data": map_data,
                "event_stats": event_stats
            }
        except Exception as e:
            logger.exception("Failed to compile dashboard data")
            return {
                "total_events": 0,
                "total_alerts": 0,
                "total_ips": 0,
                "total_countries": 0,
                "high_risk_ips": 0,
                "recent_events": [],
                "timeline": [],
                "top_countries": [],
                "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
                "map_data": [],
                "event_stats": {"total": 0, "by_status": {}, "by_source": {}, "by_type": {}}
            }