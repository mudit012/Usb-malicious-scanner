# Flask Defensive Tool (Sample)

This repository is a simple defensive tool built with Flask intended as a demo project for submission.

## Features
- Upload or paste log files to `/api/scan-logs` to detect repeated failed login attempts.
- Simple in-memory rate limiter to protect endpoints.
- Block/unblock IPs via `/api/block-ip` and `/api/unblock-ip`.
- Persistent blocklist stored in `data/blocklist.json`.
- Simple HTML dashboard at `/`.

## Quick start
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## Endpoints
- `GET /` - basic dashboard
- `POST /api/scan-logs` - upload a logfile (form field `logfile`) or send JSON `{"log": "..."}`.
- `POST /api/block-ip` - JSON `{"ip":"1.2.3.4","reason":"ssh brute"}`
- `POST /api/unblock-ip` - JSON `{"ip":"1.2.3.4"}`
- `GET /api/blocklist` - view current blocklist

## Notes
This is a demo educational tool. For production use, add authentication, persistent DB, robust rate-limiting (Redis), and integrate with system-level firewall or SIEM.
