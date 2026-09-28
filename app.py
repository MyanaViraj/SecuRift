import os
import shutil
from flask import Flask, render_template, redirect, url_for
from config import Config
from models import db, login_manager
from models.models import User
from analyzer.snort_runner import check_snort_installed
from analyzer.pcap_analyzer import check_tshark_installed, SCAPY_AVAILABLE

# Route Blueprints
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.baseline import baseline_bp
from routes.test_cases import test_cases_bp
from routes.rules import rules_bp
from routes.validation import validation_bp
from routes.false_positives import false_positives_bp
from routes.performance import performance_bp
from routes.detection_logic import detection_logic_bp
from routes.coverage import coverage_bp
from routes.severity import severity_bp
from routes.mitre import mitre_bp
from routes.snort import snort_bp
from routes.reports import reports_bp


def create_app(config_class=Config):
    """Application factory for SecuRift Network Defence Platform."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload, rules, and reports directories exist
    config_class.ensure_directories()

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    from models import csrf
    csrf.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(baseline_bp)
    app.register_blueprint(test_cases_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(validation_bp)
    app.register_blueprint(false_positives_bp)
    app.register_blueprint(performance_bp)
    app.register_blueprint(detection_logic_bp)
    app.register_blueprint(coverage_bp)
    app.register_blueprint(severity_bp)
    app.register_blueprint(mitre_bp)
    app.register_blueprint(snort_bp)
    app.register_blueprint(reports_bp)

    # Jinja template filter for number formatting
    @app.template_filter("number_format")
    def number_format(value):
        try:
            return f"{int(value):,}"
        except (ValueError, TypeError):
            return value

    # Context processor for platform health & tool availability
    @app.context_processor
    def inject_system_status():
        snort_info = check_snort_installed()
        tshark_info = check_tshark_installed()
        return {
            "system_status": {
                "flask_status": "Running",
                "database_status": "Connected (SQLite)",
                "snort_installed": bool(snort_info),
                "snort_version": snort_info.get("version", "N/A") if snort_info else "NOT INSTALLED — REAL SNORT EXECUTION UNAVAILABLE",
                "snort_path": snort_info.get("path", "") if snort_info else "",
                "tshark_installed": bool(tshark_info),
                "tshark_version": tshark_info.get("version", "N/A") if tshark_info else "Not Installed",
                "scapy_available": SCAPY_AVAILABLE,
                "upload_directories": "Ready"
            }
        }

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("base.html", active_page="dashboard"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("base.html", active_page="dashboard"), 500

    @app.errorhandler(413)
    def file_too_large(e):
        return "Uploaded file exceeds the maximum allowed security limit (50MB).", 413

    # Create tables automatically on startup
    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
