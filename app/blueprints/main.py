import logging
from flask import Blueprint, render_template, request, redirect, url_for
from app.repositories.ip_repository import IPRepository
from app.repositories.event_repository import EventRepository
from app.repositories.alert_repository import AlertRepository

logger = logging.getLogger(__name__)

main = Blueprint("main", __name__)

@main.route("/")
def dashboard():
    """Renders the main dashboard page."""
    return render_template("dashboard.html")

@main.route("/lookup")
def lookup():
    """Renders the standalone IP intelligence lookup page."""
    ip_param = request.args.get("ip", "").strip()
    return render_template("lookup.html", prefilled_ip=ip_param)

@main.route("/logs")
def logs():
    """Renders the event logs viewer."""
    return render_template("logs.html")

@main.route("/map")
def threat_map():
    """Renders the global threat map page."""
    return render_template("map.html")

@main.route("/alerts")
def alerts():
    """Renders the alerts feed page."""
    return render_template("alerts.html")

@main.route("/history")
def history():
    """Renders the IP search/lookup history page."""
    return render_template("history.html")

@main.route("/import")
def import_logs():
    """Renders the log file importer page."""
    return render_template("import.html")

@main.route("/reports")
def reports():
    """Renders reports and analytics charts."""
    return render_template("reports.html")

@main.route("/settings")
def settings():
    """Renders system settings page."""
    return render_template("settings.html")
