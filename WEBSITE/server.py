#!/usr/bin/env python3
"""
NexoVault — Servidor local simples
Uso: python3 server.py [porta]
"""

import http.server
import socketserver
import socket
import sys
import os
import webbrowser
from pathlib import Path

# ── Configuração ────────────────────────────────────────────
arg = sys.argv[1].strip() if len(sys.argv) > 1 else ""
PORT = int(arg) if arg.isdigit() else 8080
HOST = "0.0.0.0"          # 0.0.0.0 → acessível na rede local
SITE_DIR = Path(__file__).parent   # pasta onde está o index.html
# ────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE_DIR), **kwargs)

    def log_message(self, fmt, *args):
        addr = self.client_address[0]
        method_path = fmt % args
        print(f"  [{addr}]  {method_path}")

os.chdir(SITE_DIR)

print()
print("  ╔══════════════════════════════════════════╗")
print("  ║        NexoVault — Servidor Local        ║")
print("  ╚══════════════════════════════════════════╝")
print()

local_ip = get_local_ip()

with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
    httpd.allow_reuse_address = True
    print(f"  🌐  Local:    http://localhost:{PORT}")
    print(f"  🌐  Rede:     http://{local_ip}:{PORT}")
    print()
    print("  Pressiona Ctrl+C para parar o servidor.")
    print()

    try:
        webbrowser.open(f"http://localhost:{PORT}")
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print("  Servidor parado. Até logo!")
        print()
