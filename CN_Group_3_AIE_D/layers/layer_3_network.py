# layer_3_network.py
import json
import random
from config import HEADER_DELIMITER as DELIM
from utils import Colors

def encapsulate(segment, log_func, src_ip, dst_ip):
    """Add IP header to segment"""
    header = {
        "version": 4,
        "ihl": 5,
        "tos": 0,
        "total_length": len(segment) + 20,
        "identification": random.randint(10000, 65535),
        "flags": 0,
        "fragment_offset": 0,
        "ttl": 64,
        "protocol": 6,  # TCP
        "checksum": 0,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    }

    packet = json.dumps(header) + DELIM + segment

    log_func("3-Network", f"📡 IP Packet: {src_ip} → {dst_ip}")
    log_func("3-Network", f"📦 ID: {header['identification']}, TTL: {header['ttl']}, Length: {len(packet)}")

    return packet

def decapsulate(packet, log_func):
    """Extract segment from IP packet"""
    try:
        if DELIM in packet:
            header_json, segment = packet.split(DELIM, 1)
            header = json.loads(header_json)

            src_ip = header.get('src_ip', 'Unknown')
            dst_ip = header.get('dst_ip', 'Unknown')
            ttl = header.get('ttl', 0)

            log_func("3-Network", f"📡 IP Packet: {src_ip} → {dst_ip}")
            log_func("3-Network", f"📦 TTL: {ttl}, Length: {len(segment)} bytes")

            return header, segment
        else:
            log_func("3-Network", f"⚠️ Malformed packet, treating as raw segment")
            return {}, packet
    except Exception as e:
        log_func("3-Network", f"⚠️ Packet processing error: {e}")
        return {}, packet