# utils.py - Enhanced utility functions with proper Colors class

import tkinter as tk

class Colors:
    """Color constants for logging"""
    BLACK = "black"
    GREEN = "green" 
    FAIL = "red"
    CYAN = "cyan"
    WARNING = "orange"
    BOLD = "bold"
    BLUE = "blue"
    PURPLE = "purple"

def _append(widget, text, tag=None):
    """Helper function to append text to widget"""
    try:
        widget.configure(state=tk.NORMAL)
        if tag:
            widget.insert(tk.END, text + "\n", tag)
        else:
            widget.insert(tk.END, text + "\n")
        widget.see(tk.END)
        widget.configure(state=tk.DISABLED)
    except:
        pass  # Ignore widget errors if window is closed

def log_to_widget(widget, node, msg, color="black"):
    """Log message to widget with color"""
    _append(widget, f"[{node}] {msg}", color)

def log_encapsulation_to_widget(widget, layer, data):
    """Log encapsulation data to widget"""
    _append(widget, f"[{layer}][encap] {data}")

def log_decapsulation_to_widget(widget, layer, data):
    """Log decapsulation data to widget"""
    _append(widget, f"[{layer}][decap] {data}")