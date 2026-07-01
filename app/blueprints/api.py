import logging
import os
from flask import Blueprint, jsonify, request, current_app
from werkzeug.utils import secure_filename

from app.models import IPAddress, SecurityEvent, Alert
from app.services.ip_service import IPService
from app.services.dashboard_service import DashboardService
from app.services.import_service import ImportService
from app.repositories.event_repository import EventRepository
from app.repositories.alert_repository import AlertRepository
from app.repositories.ip_repository import IPRepository

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__, url_prefix="/api")

# Instantiate services and repos
ip_service = IPService()
dashboard_service = DashboardService()
import_service = ImportService()
event_repo = EventRepository()
alert_repo = AlertRepository()
ip_repo = IPRepository()

@api.route("/health")
def health():
    """Returns application health status."""
    return jsonify({
        "status": "online",
        "service": "RedEye",
        "version": "1.0.0"
    })

@api.route("/dashboard")
def get_dashboard():
    """Returns aggregated stats and records for the dashboard."""
    data = dashboard_service.get_dashboard_data()
    return jsonify(data)

@api.route("/events")
def get_events():
    """Returns paginated security events, with optional filtering."""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        source = request.args.get("source", "").strip()
        status = request.args.get("status", "").strip()
        search = request.args.get("search", "").strip()

        # Build query
        query = SecurityEvent.query
        if source:
            query = query.filter(SecurityEvent.source == source.upper())
        if status:
            query = query.filter(SecurityEvent.status == status.upper())
        if search:
            query = query.join(IPAddress).filter(
                (SecurityEvent.username.ilike(f"%{search}%")) |
                (IPAddress.ip.ilike(f"%{search}%"))
            )

        # Sort and paginate
        pagination = query.order_by(SecurityEvent.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        events_list = [e.to_dict() for e in pagination.items]
        return jsonify({
            "events": events_list,
            "total": pagination.total,
            "page": pagination.page,
            "pages": pagination.pages,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev
        })
    except Exception as e:
        logger.exception("Failed to query events")
        return jsonify({"error": "Failed to query events", "details": str(e)}), 500

@api.route("/ip/<ip>")
def get_ip(ip):
    """Returns stored IP details or performs lookup if not cached."""
    try:
        details = ip_service.get_ip_details(ip)
        if "error" in details:
            return jsonify(details), 400
        return jsonify(details)
    except Exception as e:
        logger.exception(f"Error fetching details for IP {ip}")
        return jsonify({"error": f"Failed to get details: {str(e)}"}), 500

@api.route("/ip/lookup", methods=["POST"])
def perform_lookup():
    """Performs standsalone lookup for a posted IP address."""
    try:
        data = request.get_json() or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP parameter is required"}), 400
            
        result = ip_service.lookup_and_store(ip)
        if "error" in result:
            return jsonify(result), 400
        return jsonify(result)
    except Exception as e:
        logger.exception("Error executing standalone lookup")
        return jsonify({"error": f"Lookup failed: {str(e)}"}), 500

@api.route("/ip/history")
def get_ip_history():
    """Returns list of all cached IP intelligence profiles."""
    try:
        ips = ip_repo.search("") # Return all
        return jsonify({
            "ips": [ip.to_dict() for ip in ips]
        })
    except Exception as e:
        logger.exception("Failed to get IP history")
        return jsonify({"error": str(e)}), 500

@api.route("/alerts")
def get_alerts():
    """Returns unresolved security alerts and status summary stats."""
    try:
        severity = request.args.get("severity", "").strip()
        
        # Build query
        query = Alert.query
        if severity:
            query = query.filter(Alert.severity == severity.upper())
            
        # Get unresolved first, ordered by severity and time
        alerts_list = query.order_by(Alert.resolved.asc(), Alert.created_at.desc()).all()
        
        # Compile stats
        stats = alert_repo.get_stats()

        return jsonify({
            "alerts": [a.to_dict() for a in alerts_list],
            "stats": stats
        })
    except Exception as e:
        logger.exception("Failed to query alerts")
        return jsonify({"error": str(e)}), 500

@api.route("/alerts/<int:id>/resolve", methods=["PUT"])
def resolve_alert(id):
    """Marks a security alert as resolved."""
    try:
        alert = alert_repo.resolve(id)
        if alert:
            return jsonify({"message": f"Alert {id} resolved successfully", "alert": alert.to_dict()})
        return jsonify({"error": f"Alert {id} not found"}), 404
    except Exception as e:
        logger.exception(f"Failed to resolve alert {id}")
        return jsonify({"error": str(e)}), 500

@api.route("/map/data")
def get_map_data():
    """Returns map coordinate plotting dataset."""
    try:
        data = ip_repo.get_map_data()
        return jsonify(data)
    except Exception as e:
        logger.exception("Failed to compile map data")
        return jsonify({"error": str(e)}), 500

@api.route("/import", methods=["POST"])
def import_logs():
    """Accepts log uploads and processes them through parsers and ingestion pipeline."""
    try:
        source = request.form.get("source", "").strip().lower()
        if "logfile" not in request.files:
            return jsonify({"error": "No logfile part in request"}), 400
            
        file = request.files["logfile"]
        if file.filename == "":
            return jsonify({"error": "No file selected for uploading"}), 400

        if not source:
            return jsonify({"error": "source field is required"}), 400

        # Save to upload folder
        upload_folder = current_app.config.get("UPLOAD_FOLDER", "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)

        # Import using the service
        if source == "bulk":
            result = import_service.import_bulk_ips(filepath)
        else:
            result = import_service.import_file(filepath, source)
        
        # Clean up file after import
        try:
            os.remove(filepath)
        except Exception:
            pass

        if "error" in result:
            return jsonify(result), 400

        return jsonify(result)
    except Exception as e:
        logger.exception("Inbound log import failed")
        return jsonify({"error": f"Import failed: {str(e)}"}), 500

@api.route("/clear-data", methods=["POST"])
def clear_data():
    """Truncates all database tables (IP records, security events, and alerts)."""
    try:
        Alert.query.delete()
        SecurityEvent.query.delete()
        IPAddress.query.delete()
        db.session.commit()
        logger.warning("Database reset executed: all event, alert, and IP coordinates records cleared.")
        return jsonify({"message": "All database and threat coordinates records cleared successfully"})
    except Exception as e:
        db.session.rollback()
        logger.exception("Failed to execute database reset")
        return jsonify({"error": f"Failed to reset data: {str(e)}"}), 500
