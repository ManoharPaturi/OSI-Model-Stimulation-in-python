# layer_5_session.py
import json
import random
import string
from config import HEADER_DELIMITER as DELIM
from utils import Colors

def encapsulate(data, log_func):
    """Add session layer information"""
    session_id = random.randint(1000, 9999)
    session_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    header = {
        "session_id": session_id,
        "session_token": session_token,
        "session_state": "ESTABLISHED",
        "sequence": 1
    }

    session_data = json.dumps(header) + DELIM + data

    log_func("5-Session", f"🔐 Session established: ID={session_id}, Token={session_token}")
    log_func("5-Session", f"📦 Session data prepared: {len(session_data)} bytes")

    return session_data

def decapsulate(session_data, log_func):
    """Extract data from session layer"""
    try:
        if DELIM in session_data:
            header_json, data = session_data.split(DELIM, 1)
            header = json.loads(header_json)

            session_id = header.get('session_id', 0)

            log_func("5-Session", f"🔐 Session ID: {session_id}")
            log_func("5-Session", f"📦 Session data extracted: {len(data)} bytes")

            return session_id, data
        else:
            log_func("5-Session", f"⚠️ No session header, treating as raw data")
            return 0, session_data
    except Exception as e:
        log_func("5-Session", f"⚠️ Session processing error: {e}")
        return 0, session_data