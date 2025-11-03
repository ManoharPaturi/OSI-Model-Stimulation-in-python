# config.py

# Topology ports (process sockets)
SWITCH_PORT = 9100       # clients connect to L2 switch
ROUTER_PORT = 9000       # switch uplink to router
SERVER_PORT = 8080       # router uplink to server UI

# Server addressing (destination)
SERVER_IP = "10.10.10.5"
SERVER_MAC = "FF:EE:DD:CC:BB:00"

# Router interfaces (two-sided MACs)
ROUTER_MAC_CLIENT_SIDE = "AA:BB:CC:DD:EE:01"
ROUTER_MAC_SERVER_SIDE = "FF:EE:DD:CC:BB:01"

# Two clients with distinct configs
CLIENTS = {
    "c1": {
        "name": "Client-1",
        "ip": "192.168.1.100",
        "mac": "AA:BB:CC:DD:EE:10",
        "l4_src_port": 5001
    },
    "c2": {
        "name": "Client-2",
        "ip": "192.168.1.101",
        "mac": "AA:BB:CC:DD:EE:11",
        "l4_src_port": 5002
    }
}

# Header delimiter between serialized headers and payloads
HEADER_DELIMITER = "::"

# Demo Transport segment size (MSS-like, educational)
SEGMENT_SIZE = 100

# Additional config values for layers
APP_MAIL = "mail"
MAIL_PORT = 25