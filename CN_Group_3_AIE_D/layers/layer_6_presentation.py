# layer_6_presentation.py
import json
from config import HEADER_DELIMITER as DELIM
from utils import Colors

def encapsulate(data, log_func):
    """Add presentation layer formatting"""
    # Simple Caesar cipher for demonstration
    encrypted_data = ''.join(chr((ord(c) + 3) % 256) if ord(c) < 253 else c for c in data)

    header = {
        "format": "UTF-8",
        "encryption": "Caesar-3",
        "compression": "None",
        "original_size": len(data),
        "processed_size": len(encrypted_data)
    }

    presentation_data = json.dumps(header) + DELIM + encrypted_data

    log_func("6-Presentation", f"🔐 Data encrypted: {len(data)} → {len(encrypted_data)} bytes")
    log_func("6-Presentation", f"📄 Format: UTF-8, Encryption: Caesar-3")

    return presentation_data

def decapsulate(presentation_data, log_func):
    """Extract and decrypt data"""
    try:
        if DELIM in presentation_data:
            header_json, encrypted_data = presentation_data.split(DELIM, 1)
            header = json.loads(header_json)

            # Decrypt (reverse Caesar cipher)
            decrypted_data = ''.join(chr((ord(c) - 3) % 256) if ord(c) >= 3 else c for c in encrypted_data)

            log_func("6-Presentation", f"🔓 Data decrypted: {len(encrypted_data)} → {len(decrypted_data)} bytes")
            log_func("6-Presentation", f"📄 Format: UTF-8")

            return decrypted_data
        else:
            log_func("6-Presentation", f"⚠️ No presentation header, treating as raw data")
            return presentation_data
    except Exception as e:
        log_func("6-Presentation", f"⚠️ Presentation processing error: {e}")
        return presentation_data