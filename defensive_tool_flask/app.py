from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import time
import json
from utils import LogScanner, Blocklist, RateLimiter

app = Flask(__name__)
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)

blocklist = Blocklist(os.path.join(DATA_DIR, "blocklist.json"))
scanner = LogScanner(threshold=5)  # failed attempts threshold to flag IP
rate_limiter = RateLimiter(max_requests=30, window_seconds=60)

@app.before_request
def check_blocklist_and_rate_limit():
    ip = request.remote_addr or request.environ.get("REMOTE_ADDR", "unknown")
    if blocklist.is_blocked(ip):
        return jsonify({"error": "Your IP is blocked."}), 403
    allowed, remaining = rate_limiter.allow_request(ip)
    if not allowed:
        return jsonify({"error": "Rate limit exceeded. Try later."}), 429

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan-logs", methods=["POST"])
def scan_logs():
    """
    Accepts a plain-text log file upload (form field 'logfile') or raw text in 'log' JSON field.
    Returns detected suspicious IPs and suggested actions.
    """
    if "logfile" in request.files:
        content = request.files["logfile"].read().decode("utf-8", errors="ignore")
    else:
        content = request.json.get("log", "") if request.is_json else request.form.get("log", "")
    results = scanner.scan_text(content)
    return jsonify({"suspicious_ips": results})

@app.route("/api/block-ip", methods=["POST"])
def block_ip():
    data = request.get_json() or {}
    ip = data.get("ip")
    reason = data.get("reason", "manual")
    if not ip:
        return jsonify({"error":"ip required"}), 400
    blocklist.add(ip, reason=reason)
    return jsonify({"blocked": ip})

@app.route("/api/unblock-ip", methods=["POST"])
def unblock_ip():
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error":"ip required"}), 400
    blocklist.remove(ip)
    return jsonify({"unblocked": ip})

@app.route("/api/blocklist", methods=["GET"])
def get_blocklist():
    return jsonify(blocklist.list())

@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "blocklist_count": len(blocklist.list()),
        "uptime": time.time()
    })

@app.route("/download/sample-log", methods=["GET"])
def download_sample():
    return send_from_directory(os.path.join(os.path.dirname(__file__), "data"), "sample.log", as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
