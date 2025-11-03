# layer_4_transport.py
import json
import random
import config
from config import HEADER_DELIMITER as DELIM
from utils import Colors

def chunks(s: str, n: int):
    """Yield successive n-sized chunks from s."""
    for i in range(0, len(s), n):
        yield s[i:i + n]

def encapsulate(data: str, log_func, src_port: int, dst_port: int):
    """TCP encapsulation - creates multiple segments for larger data based on SEGMENT_SIZE."""
    pieces = list(chunks(data, config.SEGMENT_SIZE))
    total = len(pieces)
    segments = []

    for idx, chunk in enumerate(pieces, 1):
        header = {
            "src_port": src_port, "dst_port": dst_port, "seq": idx, "total": total, "ack": 0,
            "flags": "PSH,ACK", "window": 2048, "checksum": 0
        }
        segment = json.dumps(header) + DELIM + chunk
        segments.append(segment)
        log_func("4-Transport", f"📦 TCP Segment {idx}/{total}: {len(chunk)} bytes")

    if total > 1:
        log_func("4-Transport", f"🔄 Message fragmented into {total} segments")
    return segments

def decapsulate(segment: str, log_func):
    """TCP decapsulation with robust parsing"""
    try:
        if DELIM in segment:
            header_json, data = segment.split(DELIM, 1)
            header = json.loads(header_json)
            idx = header.get('seq', 0)
            total = header.get('total', 1)
            log_func("4-Transport", f"📨 TCP Segment {idx}/{total}: {len(data)} bytes")
            if total > 1:
                log_func("4-Transport", f"🔧 Reassembling fragmented message")
            return header, data
        return {}, segment
    except Exception as e:
        log_func("4-Transport", f"⚠️ Parsing issue, treating as raw data: {len(segment)} bytes")
        return {}, segment

class TCPConnection:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.send_seq = random.randint(1000, 9999)
        self.recv_seq = 0
        self.send_ack = 0
        self.state = "CLOSED"
        self.cwnd = 1
        self.ssthresh = 64
        self.send_window = 2048
        self.recv_window = 2048

def tcp_3way_handshake_client(connection, log_func):
    connection.state = "SYN_SENT"
    log_func("4-Transport", f"🤝 SYN sent: seq={connection.send_seq}")
    connection.send_seq += 1
    connection.recv_seq += 1
    connection.state = "ESTABLISHED"
    log_func("4-Transport", f"✅ Connection ESTABLISHED")
    return {}, {}

def tcp_connection_teardown(connection, log_func, is_initiator=True):
    try:
        connection.state = "CLOSED"
        log_func("4-Transport", "🔚 TCP connection closed with FIN/ACK", Colors.GREEN)
    except Exception as e:
        log_func("4-Transport", f"❌ Teardown error: {e}", Colors.FAIL)