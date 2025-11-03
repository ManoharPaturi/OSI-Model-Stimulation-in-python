# layer_7_application.py
import json
from config import HEADER_DELIMITER as DELIM
from utils import Colors

def encapsulate(message, log_func, app_type="mail"):
    """Add application layer header"""
    header = {
        "application": app_type.upper(),
        "protocol_version": "1.0",
        "message_id": hash(message) % 10000,
        "timestamp": "2025-10-07T18:30:00Z"
    }

    app_data = json.dumps(header) + DELIM + message

    log_func("7-Application", f"📧 Application: {app_type.upper()} protocol")
    log_func("7-Application", f"📨 Message prepared: {len(message)} bytes")

    return app_data

def decapsulate(app_data, log_func):
    """Extract message from application layer"""
    try:
        if DELIM in app_data:
            header_json, message = app_data.split(DELIM, 1)
            header = json.loads(header_json)

            app_type = header.get('application', 'UNKNOWN')

            log_func("7-Application", f"📧 Application: {app_type} protocol")
            log_func("7-Application", f"📨 Message extracted: {len(message)} bytes")

            return app_type, message
        else:
            log_func("7-Application", f"⚠️ No application header, treating as raw message")
            return "UNKNOWN", app_data
    except Exception as e:
        log_func("7-Application", f"⚠️ Application processing error: {e}")
        return "UNKNOWN", app_data