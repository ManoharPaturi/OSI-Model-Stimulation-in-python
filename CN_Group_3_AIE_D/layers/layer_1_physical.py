# layer_1_physical.py
from utils import Colors

def encapsulate(frame, log_func):
    """Convert frame to bits for transmission"""
    bits = frame.encode('utf-8')
    bit_count = len(bits) * 8

    log_func("1-Physical", f"🔗 Converting frame to {len(bits)} bytes ({bit_count} bits)")
    log_func("1-Physical", f"📡 Simulating transmission over physical medium")

    return bits.decode('utf-8')  # Return as string for simplicity

def decapsulate(bits, log_func):
    """Convert received bits back to frame"""
    log_func("1-Physical", f"📡 Received data from physical medium")
    log_func("1-Physical", f"🔗 Converting bits back to frame format")

    return bits  # Return as-is for simplicity