from app.models import IPAddress, SecurityEvent, Alert
from app.extensions import db
from sqlalchemy import func


class DashboardService:


    def summary(self):

        return {
            "total_ips": IPAddress.query.count(),
            "total_events": SecurityEvent.query.count(),
            "total_alerts": Alert.query.count(),

            "high_risk_ips": IPAddress.query.filter(
                IPAddress.risk_score >= 70
            ).count()
        }
    

    def recent_events(self, limit=10):

        events=(
            SecurityEvent.query
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
        .all()
            
        )

        data = []

        for event in events:

            data.append({

                "username": event.username,

            "event_type": event.event_type,

            "status": event.status,

            "source": event.source,

            "time": event.created_at,

            "ip": event.ip_ref.ip if hasattr(event, 'ip_ref') and event.ip_ref else None
            })
        return data    
    
    def top_countries(self):

        rows = (

            db.session.query(

                IPAddress.country,

                func.count(IPAddress.id)

            )

            .group_by(IPAddress.country)

            .all()

        )

        return [

            {

                "country": r[0],

                "count": r[1]

            }

            for r in rows

        ]

    def get_risk_distribution(self):
        return {
            "low": IPAddress.query.filter(IPAddress.risk_score < 30).count(),
            "medium": IPAddress.query.filter(IPAddress.risk_score >= 30, IPAddress.risk_score < 60).count(),
            "high": IPAddress.query.filter(IPAddress.risk_score >= 60, IPAddress.risk_score < 80).count(),
            "critical": IPAddress.query.filter(IPAddress.risk_score >= 80).count()
        }

    def get_dashboard_data(self):
        from app.repositories.ip_repository import IPRepository
        from app.repositories.event_repository import EventRepository
        
        summary = self.summary()
        top_countries_list = self.top_countries()
        
        return {
            "total_ips": summary["total_ips"],
            "total_events": summary["total_events"],
            "total_alerts": summary["total_alerts"],
            "high_risk_ips": summary["high_risk_ips"],
            "total_countries": len(top_countries_list),
            "recent_events": self.recent_events(),
            "timeline": EventRepository.get_timeline(30),
            "risk_distribution": self.get_risk_distribution(),
            "top_countries": top_countries_list,
            "map_data": IPRepository.get_map_data()
        }