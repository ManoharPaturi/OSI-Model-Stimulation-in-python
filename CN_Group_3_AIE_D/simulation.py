# simulation.py
# FINAL VERSION: All typos and bugs fixed. All UI features included.

import tkinter as tk  # Import tkinter for GUI
from tkinter import scrolledtext, ttk, Toplevel  # Import specific tkinter widgets
import socket  # For network communication
import threading  # For running tasks in parallel
import time  # For time-related functions
import queue  # For thread-safe queues
import multiprocessing  # For running multiple processes
import sys  # For system-specific parameters and functions

# --- Configuration ---
SWITCH_PORT = 9100  # Port number for the switch
ROUTER_PORT = 9000  # Port number for the router
SERVER_PORT = 8080  # Port number for the server
SERVER_IP = "10.10.10.5"  # IP address of the server
SERVER_MAC = "FF:EE:DD:CC:BB:00"  # MAC address of the server
ROUTER_MAC_CLIENT_SIDE = "AA:BB:CC:DD:EE:01"  # Router MAC on client side
ROUTER_MAC_SERVER_SIDE = "FF:EE:DD:CC:BB:01"  # Router MAC on server side
CLIENTS = {  # Dictionary holding client configurations
    "c1": {"name": "Client-1", "ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:10", "l4_src_port": 5001},
    "c2": {"name": "Client-2", "ip": "192.168.1.101", "mac": "AA:BB:CC:DD:EE:11", "l4_src_port": 5002}
}
HEADER_DELIMITER = "::"  # Delimiter for headers (not used in this file)
SEGMENT_SIZE = 100  # Size of each segment for transport
APP_MAIL = "mail"  # Application protocol name
MAIL_PORT = 25  # Port for mail application

# --- Utilities ---
class Colors:
    BLACK, GREEN, FAIL, CYAN, WARNING, BLUE, PURPLE = "black", "green", "red", "cyan", "orange", "blue", "purple"  # Color constants

def log_to_widget(widget, node, msg, color="black"):
    try:
        if widget.winfo_exists():  # Check if widget still exists
            widget.configure(state=tk.NORMAL)  # Enable editing
            widget.insert(tk.END, f"[{node}] {msg}\n", color)  # Insert log message with color tag
            widget.see(tk.END)  # Scroll to end
            widget.configure(state=tk.DISABLED)  # Disable editing
    except tk.TclError:
        pass # Ignore errors if window is closed

# --- Layer Imports ---
from layers import layer_7_application as l7, layer_6_presentation as l6, layer_5_session as l5, layer_4_transport as l4, layer_3_network as l3, layer_2_data_link as l2, layer_1_physical as l1  # Import all OSI layers

# --- Switch Code ---
def relay_data_switch(src, dst, ui, direction):
    """Relay data and update UI counters."""
    try:
        while True:  # Loop to keep relaying data
            data = src.recv(8192)  # Receive data from source
            if not data: break  # If no data, exit loop
            dst.sendall(data)  # Send data to destination
            if direction == 'downstream': # Client -> Router
                ui.frame_count += 1  # Increment frame count
                ui.forwarded_count += 1  # Increment forwarded count
    except (ConnectionResetError, BrokenPipeError, OSError): pass  # Handle connection errors
    finally:
        try: src.close()  # Close source socket
        except: pass
        try: dst.close()  # Close destination socket
        except: pass

class SwitchUI:
    def __init__(self, root):
        self.root = root  # Store root window
        self.frame_count = 0  # Frames received
        self.forwarded_count = 0  # Frames forwarded
        self.dropped_count = 0  # Frames dropped
        self.setup_ui()  # Setup the UI
        self.log = lambda node, msg, color=Colors.BLACK: self.root.after(0, log_to_widget, self.log_widget, node, msg, color)  # Async log function
        threading.Thread(target=self.start_switch, daemon=True).start()  # Start switch server in a thread
        threading.Thread(target=self.update_ui_live, daemon=True).start()  # Start UI update thread

    def setup_ui(self):
        self.root.title("🚦 L2 Switch")  # Set window title
        self.root.geometry("950x700+1050+550")  # Set window size and position
        self.root.configure(bg="#2E2E2E")  # Set background color
        title_frame = tk.Frame(self.root, bg="#3C3C3C", bd=2, relief=tk.RIDGE)  # Title frame
        title_frame.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(title_frame, text="🚦 Layer 2 Switch - Ethernet Frame Relay", font=("Helvetica", 16, "bold"), bg="#3C3C3C", fg="white").pack(pady=10)
        
        stats_frame = tk.LabelFrame(self.root, text="📊 Switch Statistics", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white")  # Stats frame
        stats_frame.pack(padx=10, pady=5, fill=tk.X)
        self.stats_labels = {}  # Dictionary for stat labels
        stats_container = tk.Frame(stats_frame, bg="#2E2E2E")  # Container for stats
        stats_container.pack(fill=tk.X, padx=5, pady=5)
        stats_items = [("Frames Received", "0"), ("Frames Forwarded", "0"), ("Frames Dropped", "0")]  # Stat items
        for i, (label, value) in enumerate(stats_items):
            frame = tk.Frame(stats_container, bg="#3C3C3C", bd=1, relief=tk.RIDGE)  # Frame for each stat
            frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            tk.Label(frame, text=label, bg="#3C3C3C", fg="white", font=("Helvetica", 9)).pack()
            self.stats_labels[label] = tk.Label(frame, text=value, bg="#3C3C3C", fg="#4CAF50", font=("Helvetica", 14, "bold"))
            self.stats_labels[label].pack()
            
        mac_frame = tk.LabelFrame(self.root, text="📋 MAC Address Table", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white")  # MAC table frame
        mac_frame.pack(padx=10, pady=5, fill=tk.X)
        mac_tree = ttk.Treeview(mac_frame, columns=("Port", "Type"), show="headings", height=3)  # Treeview for MAC table
        mac_tree.heading("Port", text="Port"); mac_tree.heading("Type", text="Type")
        mac_tree.column("Port", width=100); mac_tree.column("Type", width=100)
        mac_tree.pack(padx=5, pady=5, fill=tk.X)
        mac_tree.insert("", "end", text=ROUTER_MAC_CLIENT_SIDE, values=("Uplink", "Static"))  # Insert router MAC
        mac_tree.insert("", "end", text=CLIENTS['c1']['mac'], values=("Port 1", "Dynamic"))  # Insert client 1 MAC
        mac_tree.insert("", "end", text=CLIENTS['c2']['mac'], values=("Port 2", "Dynamic"))  # Insert client 2 MAC

        logs_frame = tk.LabelFrame(self.root, text="📋 Switch Event Logs", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white")  # Logs frame
        logs_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.log_widget = scrolledtext.ScrolledText(logs_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Courier New", 10), bg="#1E1E1E", fg="white")  # Log widget
        self.log_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        for color_name, color_code in [("green", "#4CAF50"), ("red", "#F44336"), ("orange", "#FF9800"), ("cyan", "#00BCD4")]:
            self.log_widget.tag_config(color_name, foreground=color_code)  # Configure color tags
    
    def start_switch(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as switch_socket:  # Create TCP socket
            switch_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
            switch_socket.bind(('localhost', SWITCH_PORT))  # Bind to switch port
            switch_socket.listen(10)  # Listen for connections
            self.log("🚦 Switch", f"🚀 Started on port {SWITCH_PORT}", Colors.GREEN)  # Log start
            while True:
                client_conn, addr = switch_socket.accept()  # Accept client connection
                self.log("🚦 Switch", f"🔗 Connection from {addr}", Colors.CYAN)  # Log connection
                threading.Thread(target=self.handle_client, args=(client_conn, addr), daemon=True).start()  # Handle client in thread

    def handle_client(self, client_conn, addr):
        try:
            router_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket to router
            router_conn.connect(('localhost', ROUTER_PORT))  # Connect to router
            self.log("🚦 Switch", f"🔗 Uplink to Router for {addr} established.", Colors.GREEN)  # Log uplink
            threading.Thread(target=relay_data_switch, args=(client_conn, router_conn, self, 'downstream'), daemon=True).start()  # Relay downstream
            threading.Thread(target=relay_data_switch, args=(router_conn, client_conn, self, 'upstream'), daemon=True).start()  # Relay upstream
        except Exception as e:
            self.log("🚦 Switch", f"❌ Uplink failed for {addr}: {e}", Colors.FAIL)  # Log failure
            client_conn.close()  # Close client connection

    def update_ui_live(self):
        while True:
            try:
                self.root.after(0, self.refresh_stats)  # Schedule stats refresh
                time.sleep(1)  # Wait 1 second
            except: break

    def refresh_stats(self):
        try:
            self.stats_labels["Frames Received"].configure(text=str(self.frame_count))  # Update received count
            self.stats_labels["Frames Forwarded"].configure(text=str(self.forwarded_count))  # Update forwarded count
        except: pass

# --- Router Code ---
def relay_data_router(src, dst, ui, direction):
    try:
        while True:
            data = src.recv(8192)  # Receive data from source
            if not data: break  # If no data, exit loop
            dst.sendall(data)  # Send data to destination
            if direction == 'downstream':
                ui.packet_count += 1  # Increment packet count
                ui.forwarded_count += 1  # Increment forwarded count
    except (ConnectionResetError, BrokenPipeError, OSError): pass  # Handle connection errors
    finally:
        try: src.close()  # Close source socket
        except: pass
        try: dst.close()  # Close destination socket
        except: pass

class RouterUI:
    def __init__(self, root):
        self.root = root  # Store root window
        self.packet_count = 0  # Packets received
        self.forwarded_count = 0  # Packets forwarded
        self.dropped_count = 0  # Packets dropped
        self.setup_ui()  # Setup the UI
        self.log = lambda node, msg, color=Colors.BLACK: self.root.after(0, log_to_widget, self.log_widget, node, msg, color)  # Async log function
        threading.Thread(target=self.start_router, daemon=True).start()  # Start router server in a thread
        threading.Thread(target=self.update_ui_live, daemon=True).start()  # Start UI update thread

    def setup_ui(self):
        self.root.title("🌐 L3 Router")  # Set window title
        self.root.geometry("950x700+1050+0")  # Set window size and position
        self.root.configure(bg="#2E2E2E")  # Set background color
        title_frame = tk.Frame(self.root, bg="#3C3C3C", bd=2, relief=tk.RIDGE)  # Title frame
        title_frame.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(title_frame, text="🌐 Layer 3 Router - IP Packet Relay", font=("Helvetica", 16, "bold"), bg="#3C3C3C", fg="white").pack(pady=10)
        
        stats_frame = tk.LabelFrame(self.root, text="📊 Router Statistics", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white")  # Stats frame
        stats_frame.pack(padx=10, pady=5, fill=tk.X)
        self.stats_labels = {}  # Dictionary for stat labels
        stats_container = tk.Frame(stats_frame, bg="#2E2E2E")  # Container for stats
        stats_container.pack(fill=tk.X, padx=5, pady=5)
        stats_items = [("Packets Received", "0"), ("Packets Forwarded", "0"), ("Packets Dropped", "0")]  # Stat items
        for i, (label, value) in enumerate(stats_items):
            frame = tk.Frame(stats_container, bg="#3C3C3C", bd=1, relief=tk.RIDGE)  # Frame for each stat
            frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            tk.Label(frame, text=label, bg="#3C3C3C", fg="white", font=("Helvetica", 9)).pack()
            self.stats_labels[label] = tk.Label(frame, text=value, bg="#3C3C3C", fg="#4CAF50", font=("Helvetica", 14, "bold"))
            self.stats_labels[label].pack()
        
        route_frame = tk.LabelFrame(self.root, text="🗺️ Routing Table", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white")  # Routing table frame
        route_frame.pack(padx=10, pady=5, fill=tk.X)
        route_tree = ttk.Treeview(route_frame, columns=("Next Hop", "Interface"), show="headings", height=2)  # Treeview for routing table
        route_tree.heading("Next Hop", text="Next Hop"); route_tree.heading("Interface", text="Interface")
        route_tree.pack(padx=5, pady=5, fill=tk.X)
        route_tree.insert("", "end", text="10.10.10.0/24", values=("On-link", "eth1"))  # Insert server network
        route_tree.insert("", "end", text="192.168.1.0/24", values=("On-link", "eth0"))  # Insert client network

        logs_frame = tk.LabelFrame(self.root, text="📋 Router Event Logs", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white")  # Logs frame
        logs_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.log_widget = scrolledtext.ScrolledText(logs_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Courier New", 10), bg="#1E1E1E", fg="white")  # Log widget
        self.log_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        for color_name, color_code in [("green", "#4CAF50"), ("red", "#F44336"), ("orange", "#FF9800"), ("cyan", "#00BCD4")]:
            self.log_widget.tag_config(color_name, foreground=color_code)  # Configure color tags
            
    def start_router(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as router_socket:  # Create TCP socket
            router_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
            router_socket.bind(('localhost', ROUTER_PORT))  # Bind to router port
            router_socket.listen(10)  # Listen for connections
            self.log("🌐 Router", f"🚀 Started on port {ROUTER_PORT}", Colors.GREEN)  # Log start
            while True:
                switch_conn, addr = router_socket.accept()  # Accept switch connection
                self.log("🌐 Router", f"🔗 Connection from {addr}", Colors.CYAN)  # Log connection
                threading.Thread(target=self.handle_switch, args=(switch_conn, addr), daemon=True).start()  # Handle switch in thread

    def handle_switch(self, switch_conn, addr):
        try:
            server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket to server
            server_conn.connect(('localhost', SERVER_PORT))  # Connect to server
            self.log("🌐 Router", f"🔗 Uplink to Server for {addr} established.", Colors.GREEN)  # Log uplink
            threading.Thread(target=relay_data_router, args=(switch_conn, server_conn, self, 'downstream'), daemon=True).start()  # Relay downstream
            threading.Thread(target=relay_data_router, args=(server_conn, switch_conn, self, 'upstream'), daemon=True).start()  # Relay upstream
        except Exception as e:
            self.log("🌐 Router", f"❌ Uplink failed for {addr}: {e}", Colors.FAIL)  # Log failure
            switch_conn.close()  # Close switch connection
    
    def update_ui_live(self):
        while True:
            try:
                self.root.after(0, self.refresh_stats)  # Schedule stats refresh
                time.sleep(1)  # Wait 1 second
            except: break

    def refresh_stats(self):
        try:
            self.stats_labels["Packets Received"].configure(text=str(self.packet_count))  # Update received count
            self.stats_labels["Packets Forwarded"].configure(text=str(self.forwarded_count))  # Update forwarded count
        except: pass

# --- Server Code ---
class ClientHandler:
    def __init__(self, server_ui, conn, addr):
        self.server_ui, self.conn, self.addr = server_ui, conn, addr  # Store references
        self.outgoing_queue, self.is_running, self.client_ip = queue.Queue(), True, None  # Outgoing queue, running flag, client IP
    def start(self):
        threading.Thread(target=self.receiver_thread, daemon=True).start()  # Start receiver thread
        threading.Thread(target=self.sender_thread, daemon=True).start()  # Start sender thread
    def stop(self):
        self.is_running = False  # Set running flag to False
        self.conn.close()  # Close connection
        self.server_ui.remove_client(self.addr)  # Remove client from UI
    def send(self, message): self.outgoing_queue.put(message)  # Add message to outgoing queue
    def receiver_thread(self):
        segments_buffer, total_segments, dummy_log = {}, 0, lambda *args: None  # Buffer for segments, total segments, dummy log
        while self.is_running:
            try:
                header_bytes = self.conn.recv(10)  # Receive header (length)
                if not header_bytes: break  # If no header, exit
                frame_len = int(header_bytes.decode('utf-8').strip())  # Parse frame length
                frame_bytes = b''
                while len(frame_bytes) < frame_len:  # Receive full frame
                    chunk = self.conn.recv(frame_len - len(frame_bytes))
                    if not chunk: raise ConnectionError()
                    frame_bytes += chunk
                raw_data = frame_bytes.decode('utf-8')  # Decode frame
                is_first = len(segments_buffer) == 0  # Check if first segment
                log_func = self.server_ui.log if is_first else dummy_log  # Use log only for first
                bits = l1.decapsulate(raw_data, log_func)  # Decapsulate physical
                _, l3_packet = l2.decapsulate(bits, log_func)  # Decapsulate data link
                l3_header, l4_segment = l3.decapsulate(l3_packet, log_func)  # Decapsulate network
                if not self.client_ip: self.client_ip = l3_header.get('src_ip')  # Set client IP
                l4_header, l5_data_part = l4.decapsulate(l4_segment, self.server_ui.log)  # Decapsulate transport
                seq = l4_header.get('seq')  # Get sequence number
                if seq:
                    segments_buffer[seq] = l5_data_part  # Store segment
                    total_segments = l4_header.get('total', 1)  # Get total segments
                    self.server_ui.root.after(0, self.server_ui._update_progress, len(segments_buffer), total_segments)  # Update progress bar
                if total_segments > 0 and len(segments_buffer) >= total_segments:  # If all segments received
                    full_message = "".join(segments_buffer[i] for i in sorted(segments_buffer.keys()))  # Reassemble message
                    self.process_message(full_message)  # Process message
                    segments_buffer.clear()  # Clear buffer
            except (ConnectionError, ValueError, IndexError, OSError): break  # Handle errors
        self.stop()  # Stop handler
    def sender_thread(self):
        dummy_log = lambda *args: None  # Dummy log function
        while self.is_running:
            try:
                message = self.outgoing_queue.get(timeout=1)  # Get message from queue
                l7_data = l7.encapsulate(message, self.server_ui.log, "mail_response")  # Encapsulate application
                l6_data = l6.encapsulate(l7_data, self.server_ui.log)  # Encapsulate presentation
                l5_data = l5.encapsulate(l6_data, self.server_ui.log)  # Encapsulate session
                client_port = CLIENTS['c1']['l4_src_port'] if self.client_ip == CLIENTS['c1']['ip'] else CLIENTS['c2']['l4_src_port']  # Get client port
                l4_segments = l4.encapsulate(l5_data, self.server_ui.log, MAIL_PORT, client_port)  # Encapsulate transport
                for i, segment in enumerate(l4_segments):  # For each segment
                    log_func = self.server_ui.log if i == 0 else dummy_log  # Log only first
                    l3_packet = l3.encapsulate(segment, log_func, SERVER_IP, self.client_ip)  # Encapsulate network
                    l2_frame = l2.encapsulate(l3_packet, log_func, SERVER_MAC, ROUTER_MAC_SERVER_SIDE)  # Encapsulate data link
                    bits = l1.encapsulate(l2_frame, log_func)  # Encapsulate physical
                    frame_data = bits.encode('utf-8')  # Encode to bytes
                    header = f"{len(frame_data):<10}".encode('utf-8')  # Create header
                    self.conn.sendall(header + frame_data)  # Send frame
                self.server_ui.root.after(0, self.server_ui._update_sent_message_count, self.client_ip, message)  # Update sent count
            except queue.Empty: continue  # If queue empty, continue
            except Exception as e:
                if self.is_running: self.server_ui.log("📤 Sender", f"Error for {self.addr}: {e}", Colors.FAIL)  # Log error
                break
        self.stop()  # Stop handler
    def process_message(self, l5_data):
        _, l6_data = l5.decapsulate(l5_data, self.server_ui.log)  # Decapsulate session
        l7_data = l6.decapsulate(l6_data, self.server_ui.log)  # Decapsulate presentation
        _, final_message = l7.decapsulate(l7_data, self.server_ui.log)  # Decapsulate application
        if final_message:
            self.server_ui.root.after(0, self.server_ui._update_received_messages_ui, self.client_ip, final_message)  # Update UI
            response = self.server_ui.custom_response.get("1.0", tk.END).strip()  # Get custom response
            self.send(response)  # Send response
class ServerUI:
    def __init__(self, root):
        self.root, self.client_handlers, self.sent_count = root, {}, 0  # Store root, handlers, sent count
        root.title("🖥️ OSI Server"); root.geometry("1000x1050+0+0")  # Set window title and size
        root.configure(bg="#2E2E2E"); self.setup_ui()  # Set background and setup UI
        self.log = lambda node, msg, color=Colors.BLACK: self.root.after(0, log_to_widget, self.log_widget, node, msg, color)  # Async log function
        threading.Thread(target=self.start_server, daemon=True).start()  # Start server in thread
    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#2E2E2E"); main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)  # Main frame
        left_frame = tk.Frame(main_frame, bg="#2E2E2E"); left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))  # Left frame
        right_frame = tk.Frame(main_frame, bg="#2E2E2E"); right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)  # Right frame
        logs_frame = tk.LabelFrame(left_frame, text="📋 Server Logs", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); logs_frame.pack(fill=tk.BOTH, expand=True)  # Logs frame
        self.log_widget = scrolledtext.ScrolledText(logs_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Courier New", 9), bg="#1E1E1E", fg="white"); self.log_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Log widget
        response_frame = tk.LabelFrame(right_frame, text="📤 Custom Server Response", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); response_frame.pack(fill=tk.X, pady=(0, 5))  # Response frame
        self.custom_response = tk.Text(response_frame, height=5, bg="#555555", fg="white", insertbackground="white", wrap=tk.WORD); self.custom_response.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Response text
        self.custom_response.insert("1.0", "✅ Got it! This is a custom reply from the server.")  # Default response
        received_frame = tk.LabelFrame(right_frame, text="📬 Received Messages", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); received_frame.pack(fill=tk.BOTH, expand=True, pady=(5,0))  # Received frame
        self.received_messages = scrolledtext.ScrolledText(received_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Arial", 10), bg="#1E1E1E", fg="#4CAF50"); self.received_messages.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Received messages
        self.receiving_progress = ttk.Progressbar(received_frame, orient='horizontal', mode='determinate'); self.receiving_progress.pack(fill=tk.X, padx=5, pady=(0, 5))  # Progress bar
        for color_name, color_code in [("green", "#4CAF50"), ("red", "#F44336"), ("orange", "#FF9800"), ("cyan", "#00BCD4")]: self.log_widget.tag_config(color_name, foreground=color_code)  # Color tags
    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:  # Create TCP socket
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); server_socket.bind(('localhost', SERVER_PORT)); server_socket.listen(10)  # Bind and listen
            self.log("🖥️ Server", f"🚀 Started on port {SERVER_PORT}", Colors.GREEN)  # Log start
            while True:
                conn, addr = server_socket.accept(); self.log("🖥️ Server", f"🔗 Connection from {addr}", Colors.CYAN)  # Accept connection and log
                handler = ClientHandler(self, conn, addr); self.client_handlers[addr] = handler; handler.start()  # Start handler
    def remove_client(self, addr):
        if addr in self.client_handlers: del self.client_handlers[addr]  # Remove client handler
    def _update_progress(self, current, total):
        self.receiving_progress['maximum'] = total; self.receiving_progress['value'] = current  # Update progress bar
        if current >= total: self.root.after(2000, lambda: self._update_progress(0, 1))  # Reset after complete
    def _update_received_messages_ui(self, client_ip, message):
        timestamp = time.strftime("%H:%M:%S"); client_name = "Client-1" if client_ip == CLIENTS['c1']['ip'] else "Client-2"  # Get client name
        self.received_messages.config(state=tk.NORMAL); self.received_messages.insert(tk.END, f"--- {timestamp} From: {client_name} ---\n{message}\n\n"); self.received_messages.see(tk.END); self.received_messages.config(state=tk.DISABLED)  # Insert message
    def _update_sent_message_count(self, client_ip, message): self.sent_count += 1  # Increment sent count
class ClientUI:
    def __init__(self, root, client_cfg: dict):
        self.root, self.cfg, self.client_socket, self.is_connected = root, client_cfg, None, False  # Store root, config, socket, connection status
        self.outgoing_queue, self.incoming_queue = queue.Queue(), queue.Queue()  # Outgoing and incoming queues
        root.title(f"📱 {self.cfg['name']}"); root.geometry("1000x800" if client_cfg['name'] == "Client-1" else "1000x800+0+550")  # Set window title and size
        root.configure(bg="#2E2E2E"); self.setup_ui()  # Set background and setup UI
        self.log = lambda node, msg, color=Colors.BLACK: self.root.after(0, log_to_widget, self.log_widget, node, msg, color)  # Async log function
    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#2E2E2E"); main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)  # Main frame
        left_frame = tk.Frame(main_frame, bg="#2E2E2E", width=350); left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))  # Left frame
        right_frame = tk.Frame(main_frame, bg="#2E2E2E"); right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)  # Right frame
        conn_frame = tk.LabelFrame(left_frame, text="🔗 Connection", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); conn_frame.pack(fill=tk.X, pady=(0, 5))  # Connection frame
        self.status_label = tk.Label(conn_frame, text="🔴 Disconnected", bg="#2E2E2E", fg="#F44336", font=("Arial", 10, "bold")); self.status_label.pack(pady=5)  # Status label
        btn_frame = tk.Frame(conn_frame, bg="#2E2E2E"); btn_frame.pack(fill=tk.X, padx=5, pady=5)  # Button frame
        self.connect_btn = tk.Button(btn_frame, text="🤝 Connect", command=self.connect_to_network, bg="#4CAF50", fg="white"); self.connect_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,5))  # Connect button
        self.disconnect_btn = tk.Button(btn_frame, text="👋 Disconnect", command=self.disconnect_from_network, bg="#F44336", fg="white", state=tk.DISABLED); self.disconnect_btn.pack(side=tk.LEFT, expand=True, fill=tk.X)  # Disconnect button
        compose_frame = tk.LabelFrame(left_frame, text="✉️ Compose", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); compose_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))  # Compose frame
        self.message_entry = tk.Text(compose_frame, height=10, bg="#555555", fg="white", insertbackground="white", wrap=tk.WORD); self.message_entry.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Message entry
        self.message_entry.insert("1.0", f"Hello from {self.cfg['name']}!"); self.send_button = tk.Button(compose_frame, text="📤 Send", command=self.send_message, bg="#2196F3", fg="white", state=tk.DISABLED); self.send_button.pack(fill=tk.X, padx=5, pady=5)  # Send button
        self.sending_progress = ttk.Progressbar(compose_frame, orient='horizontal', mode='determinate'); self.sending_progress.pack(fill=tk.X, padx=5, pady=(0, 5))  # Sending progress bar
        logs_frame = tk.LabelFrame(left_frame, text="📋 Logs", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); logs_frame.pack(fill=tk.BOTH, expand=True, pady=(5,0))  # Logs frame
        self.log_widget = scrolledtext.ScrolledText(logs_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Courier New", 9), bg="#1E1E1E", fg="white"); self.log_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Log widget
        sent_frame = tk.LabelFrame(right_frame, text="📤 Sent", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); sent_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))  # Sent frame
        self.sent_messages = scrolledtext.ScrolledText(sent_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Arial", 10), bg="#1E1E1E", fg="#2196F3"); self.sent_messages.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Sent messages
        received_frame = tk.LabelFrame(right_frame, text="📬 Received", font=("Helvetica", 12, "bold"), bg="#2E2E2E", fg="white"); received_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))  # Received frame
        self.received_messages = scrolledtext.ScrolledText(received_frame, state=tk.DISABLED, wrap=tk.WORD, font=("Arial", 10), bg="#1E1E1E", fg="#4CAF50"); self.received_messages.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Received messages
        self.receiving_progress = ttk.Progressbar(received_frame, orient='horizontal', mode='determinate'); self.receiving_progress.pack(fill=tk.X, padx=5, pady=(0, 5))  # Receiving progress bar
        for color_name, color_code in [("green", "#4CAF50"), ("red", "#F44336"), ("orange", "#FF9800"), ("cyan", "#00BCD4"), ("blue", "#2196F3")]: self.log_widget.tag_config(color_name, foreground=color_code)  # Color tags
    def connect_to_network(self):
        if self.is_connected: return  # If already connected, do nothing
        self.connect_btn.config(state=tk.DISABLED); threading.Thread(target=self._connect_thread, daemon=True).start()  # Disable button and start connect thread
    def _connect_thread(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect(('localhost', SWITCH_PORT))  # Create and connect socket
            self.client_socket = sock; self.is_connected = True  # Store socket and set connected
            threading.Thread(target=self.sender_thread, daemon=True).start(); threading.Thread(target=self.receiver_thread, daemon=True).start()  # Start sender and receiver threads
            self.log("📱 Client", "✅ Connected.", Colors.GREEN); self.root.after(0, self.update_ui_for_connection); self.root.after(100, self.process_incoming_queue)  # Log and update UI
        except Exception as e:
            self.log("📱 Client", f"❌ Connection failed: {e}", Colors.FAIL); self.root.after(0, lambda: self.connect_btn.config(state=tk.NORMAL))  # Log error and re-enable button
    def disconnect_from_network(self):
        if not self.is_connected: return  # If not connected, do nothing
        self.is_connected = False  # Set disconnected
        if self.client_socket: self.client_socket.close()  # Close socket
        self.log("📱 Client", "👋 Disconnected.", Colors.WARNING); self.update_ui_for_disconnection()  # Log and update UI
    def update_ui_for_connection(self): self.status_label.config(text="🟢 Connected", fg="#4CAF50"); self.connect_btn.config(state=tk.DISABLED); self.disconnect_btn.config(state=tk.NORMAL); self.send_button.config(state=tk.NORMAL)  # Update UI for connection
    def update_ui_for_disconnection(self): self.status_label.config(text="🔴 Disconnected", fg="#F44336"); self.connect_btn.config(state=tk.NORMAL); self.disconnect_btn.config(state=tk.DISABLED); self.send_button.config(state=tk.DISABLED)  # Update UI for disconnection
    def sender_thread(self):
        while self.is_connected:
            try:
                message = self.outgoing_queue.get(timeout=1); self._send_message_logic(message)  # Get message and send
            except queue.Empty: continue  # If queue empty, continue
            except Exception as e:
                if self.is_connected: self.log("📤 Sender", f"Error: {e}", Colors.FAIL)  # Log error
                break
    def receiver_thread(self):
        segments, total_segs, dummy_log = {}, 0, lambda *args: None  # Buffer for segments, total segments, dummy log
        while self.is_connected:
            try:
                header = self.client_socket.recv(10)  # Receive header (length)
                if not header: break  # If no header, exit
                frame_len = int(header.decode('utf-8').strip())  # Parse frame length
                frame_bytes = b''
                while len(frame_bytes) < frame_len:  # Receive full frame
                    chunk = self.client_socket.recv(frame_len - len(frame_bytes))
                    if not chunk: raise ConnectionError()
                    frame_bytes += chunk
                raw_data = frame_bytes.decode('utf-8')  # Decode frame
                log_func = self.log if len(segments) == 0 else dummy_log  # Use log only for first
                bits = l1.decapsulate(raw_data, log_func)  # Decapsulate physical
                _, l3_packet = l2.decapsulate(bits, log_func)  # Decapsulate data link
                _, l4_segment = l3.decapsulate(l3_packet, log_func)  # Decapsulate network
                l4_header, l5_data_part = l4.decapsulate(l4_segment, self.log)  # Decapsulate transport
                seq = l4_header.get('seq')  # Get sequence number
                if seq:
                    segments[seq] = l5_data_part; total_segs = l4_header.get('total', 1)  # Store segment and total
                    self.root.after(0, self._update_progress, self.receiving_progress, len(segments), total_segs)  # Update progress bar
                if total_segs > 0 and len(segments) >= total_segs:  # If all segments received
                    full_msg = "".join(segments[i] for i in sorted(segments.keys())); self.incoming_queue.put(full_msg); segments.clear()  # Reassemble and queue message
            except (ConnectionError, ValueError, IndexError, OSError):
                if self.is_connected: self.root.after(0, self.disconnect_from_network)  # Disconnect on error
                break
    def process_incoming_queue(self):
        try:
            while not self.incoming_queue.empty():
                l5_data = self.incoming_queue.get_nowait()  # Get message from queue
                _, l6_data = l5.decapsulate(l5_data, self.log)  # Decapsulate session
                l7_data = l6.decapsulate(l6_data, self.log)  # Decapsulate presentation
                _, final_message = l7.decapsulate(l7_data, self.log)  # Decapsulate application
                if final_message: self.display_received_message(final_message)  # Display message
                self.root.after(2000, self._reset_progress, self.receiving_progress)  # Reset progress bar
        finally:
            if self.is_connected: self.root.after(100, self.process_incoming_queue)  # Schedule next check
    def send_message(self):
        message = self.message_entry.get("1.0", tk.END).strip()  # Get message from entry
        if not message: return  # If empty, do nothing
        self.outgoing_queue.put(message); self.display_sent_message(message)  # Queue and display message
    def _send_message_logic(self, message):
        threading.Thread(target=self.__send_message_thread, args=(message,), daemon=True).start()  # Start send thread
    def __send_message_thread(self, message):
        l7_d = l7.encapsulate(message, self.log); l6_d = l6.encapsulate(l7_d, self.log); l5_d = l5.encapsulate(l6_d, self.log)  # Encapsulate up to session
        l4_segs = l4.encapsulate(l5_d, self.log, self.cfg['l4_src_port'], MAIL_PORT); total_s = len(l4_segs)  # Encapsulate transport
        self.root.after(0, self._update_progress, self.sending_progress, 0, total_s)  # Update progress bar
        dummy_log = lambda *args: None
        for i, seg in enumerate(l4_segs):
            log_f = self.log if i == 0 else dummy_log  # Log only first
            l3_p = l3.encapsulate(seg, log_f, self.cfg['ip'], SERVER_IP)  # Encapsulate network
            l2_f = l2.encapsulate(l3_p, log_f, self.cfg['mac'], ROUTER_MAC_CLIENT_SIDE)  # Encapsulate data link
            bits = l1.encapsulate(l2_f, log_f); frame_d = bits.encode('utf-8')  # Encapsulate physical
            header = f"{len(frame_d):<10}".encode('utf-8')  # Create header
            self.client_socket.sendall(header + frame_d)  # Send frame
            self.root.after(0, self._update_progress, self.sending_progress, i + 1, total_s)  # Update progress bar
        self.log("📤 Sending", "✅ Message sent!", Colors.GREEN); self.root.after(2000, self._reset_progress, self.sending_progress)  # Log and reset progress
    def display_sent_message(self, message): self.root.after(0, self._update_text_widget, self.sent_messages, f"📤 Sent:\n{message}")  # Display sent message
    def display_received_message(self, message): self.root.after(0, self._update_text_widget, self.received_messages, f"📬 Received:\n{message}")  # Display received message
    def _update_text_widget(self, widget, message):
        timestamp = time.strftime("%H:%M:%S"); widget.config(state=tk.NORMAL)  # Get timestamp and enable widget
        widget.insert(tk.END, f"--- {timestamp} ---\n{message}\n\n"); widget.see(tk.END); widget.config(state=tk.DISABLED)  # Insert message and disable
    def _update_progress(self, p_bar, val, max_val): p_bar['maximum'] = max_val; p_bar['value'] = val  # Update progress bar
    def _reset_progress(self, p_bar): p_bar['value'] = 0  # Reset progress bar

# --- Main Application Launcher ---
def run_component(component_class, *args):
    root = tk.Tk()  # Create Tkinter root window
    app = component_class(root, *args)  # Instantiate component
    root.mainloop()  # Start main loop

if __name__ == "__main__":
    # This is required for multiprocessing to work correctly on macOS and Windows
    if sys.platform.startswith('darwin') or sys.platform.startswith('win'):
        multiprocessing.set_start_method('spawn')  # Set multiprocessing start method
    
    components = [(ServerUI,), (RouterUI,), (SwitchUI,), (ClientUI, CLIENTS['c1']), (ClientUI, CLIENTS['c2'])]  # List of components to run
    processes = [multiprocessing.Process(target=run_component, args=(c, *a)) for c, *a in components]  # Create process for each component
    for p in processes: p.start(); time.sleep(0.3)  # Start each process with delay
    # The main process does not join the children, allowing them to run independently.