# layer_2_data_link.py
import json
from config import HEADER_DELIMITER as DELIM
from utils import Colors

def encapsulate(packet, log_func, src_mac, dst_mac):
    """Add Ethernet frame header"""
    header = {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "ethertype": "0800",  # IPv4
        "frame_check_seq": "ABCD1234"
    }

    frame = json.dumps(header) + DELIM + packet

    log_func("2-Data Link", f"🔗 Ethernet Frame: {src_mac} → {dst_mac}")
    log_func("2-Data Link", f"📦 Frame Length: {len(frame)} bytes, Type: 0800")

    return frame

def decapsulate(frame, log_func):
    """Extract packet from Ethernet frame"""
    try:
        if DELIM in frame:
            header_json, packet = frame.split(DELIM, 1)
            header = json.loads(header_json)

            src_mac = header.get('src_mac', 'Unknown')
            dst_mac = header.get('dst_mac', 'Unknown')

            log_func("2-Data Link", f"🔗 Ethernet Frame: {src_mac} → {dst_mac}")
            log_func("2-Data Link", f"📦 Frame processed: {len(packet)} bytes")

            return header, packet
        else:
            log_func("2-Data Link", f"⚠️ Malformed frame, treating as raw packet")
            return {}, frame
    except Exception as e:
        log_func("2-Data Link", f"⚠️ Frame processing error: {e}")
        return {}, frame