import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from detector import analyze_url
import database

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
    storage_uri="memory://"
)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description),
        "tip": "Pass a valid developer API key in the 'X-API-Key' header (e.g. pg_live_demo_key_2026) for elevated quota."
    }), 429


# ══════════════════════════════════════════════
# Web Pages & Views
# ══════════════════════════════════════════════

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    stats = database.get_threat_stats()
    recent_scans = database.get_recent_scans(limit=20)
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans)

@app.route("/report/<scan_id>")
def view_report(scan_id):
    scan_data = database.get_scan(scan_id)
    if not scan_data:
        return redirect(url_for("home"))
    return render_template("report.html", scan=scan_data)

@app.route("/docs")
def swagger_docs():
    return render_template("docs.html")


# ══════════════════════════════════════════════
# REST API Endpoints (v1)
# ══════════════════════════════════════════════

def get_scan_rate_limit():
    key = request.headers.get("X-API-Key")
    if key and database.is_valid_api_key(key):
        return "120 per minute"
    return "30 per minute"

@app.route("/analyze", methods=["POST"])
@limiter.limit("60 per minute")
def analyze():
    """Main Web Scanner endpoint (saves scan and returns incident ID)."""
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL to scan."}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = analyze_url(url)
    incident_id = database.save_scan(result)
    result["incident_id"] = incident_id
    result["report_url"] = f"/report/{incident_id}"

    return jsonify(result)

@app.route("/api/v1/scan", methods=["POST"])
@limiter.limit(get_scan_rate_limit)
def api_scan():
    """Public Developer REST API scan endpoint."""
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' parameter in request body."}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = analyze_url(url)
    incident_id = database.save_scan(result)
    result["incident_id"] = incident_id
    result["report_url"] = f"/report/{incident_id}"

    return jsonify(result)

@app.route("/api/v1/report/<scan_id>", methods=["GET"])
@limiter.limit("60 per minute")
def api_get_report(scan_id):
    """Fetches persistent report JSON for a previous scan."""
    scan_data = database.get_scan(scan_id)
    if not scan_data:
        return jsonify({"error": f"Scan '{scan_id}' not found."}), 404
    return jsonify(scan_data)

@app.route("/api/v1/stats", methods=["GET"])
@limiter.limit("60 per minute")
def api_stats():
    """Returns aggregated threat intelligence statistics."""
    stats = database.get_threat_stats()
    return jsonify(stats)

@app.route("/api/v1/community/report", methods=["POST"])
@limiter.limit("20 per minute")
def api_community_report():
    """Submits a false positive or new phishing link to community feed."""
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    report_type = data.get("report_type", "new_phish")
    comment = data.get("comment", "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' parameter."}), 400

    report_id = database.add_community_report(url, report_type, comment)
    return jsonify({
        "status": "success",
        "report_id": report_id,
        "message": "Report submitted to PhishGuard intelligence."
    })


# ══════════════════════════════════════════════
# OpenAPI 3.0 Specification
# ══════════════════════════════════════════════

@app.route("/openapi.json")
def openapi_spec():
    return jsonify({
        "openapi": "3.0.3",
        "info": {
            "title": "PhishGuard Threat Intelligence API",
            "description": "Production-grade automated URL threat analysis, Shannon entropy calculation, typosquatting lookalike detection, and live OSINT telemetry.",
            "version": "2.0.0",
            "contact": {
                "name": "Angad Singh Maan",
                "url": "https://github.com/angadmaan"
            }
        },
        "servers": [
            {"url": "/", "description": "Current Environment"}
        ],
        "paths": {
            "/api/v1/scan": {
                "post": {
                    "summary": "Analyze URL for Threats",
                    "description": "Executes the 17-point PhishGuard Threat Analysis Suite including Shannon Entropy, Levenshtein typosquatting, RDAP domain age, and live SSL/DNS telemetry.",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "description": "Developer API Key for elevated rate limits (Demo key: pg_live_demo_key_2026)",
                            "required": False,
                            "schema": {"type": "string", "example": "pg_live_demo_key_2026"}
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["url"],
                                    "properties": {
                                        "url": {"type": "string", "example": "https://paypa1-security.com/login"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Threat analysis completed"},
                        "400": {"description": "Missing or invalid URL"},
                        "429": {"description": "Rate limit exceeded"}
                    }
                }
            },
            "/api/v1/report/{scan_id}": {
                "get": {
                    "summary": "Get Stored Scan Report",
                    "parameters": [
                        {
                            "name": "scan_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string", "example": "PG-A1B2C3D4"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Scan details returned"},
                        "404": {"description": "Scan not found"}
                    }
                }
            },
            "/api/v1/stats": {
                "get": {
                    "summary": "Global Threat Telemetry Metrics",
                    "responses": {
                        "200": {"description": "Telemetry statistics returned"}
                    }
                }
            },
            "/api/v1/community/report": {
                "post": {
                    "summary": "Submit Community Threat or False Positive",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["url"],
                                    "properties": {
                                        "url": {"type": "string", "example": "https://suspicious-site.com"},
                                        "report_type": {"type": "string", "enum": ["new_phish", "false_positive"], "example": "new_phish"},
                                        "comment": {"type": "string", "example": "Deceptive login page"}
                                    }
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Report recorded"}
                }
            }
        }
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(debug=True, port=port)