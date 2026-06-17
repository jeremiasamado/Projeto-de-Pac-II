#!/usr/bin/env python3
"""
NexoVault — Servidor local com HTTPS + SQLi vulnerável
Uso: python3 server.py [porta]
"""

import http.server
import socketserver
import socket
import ssl
import sys
import os
import subprocess
import webbrowser
import sqlite3
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ── Configuração ────────────────────────────────────────────
arg = sys.argv[1].strip() if len(sys.argv) > 1 else ""
PORT = int(arg) if arg.isdigit() else 8443
HOST = "0.0.0.0"
SITE_DIR = Path(__file__).parent
CERT_FILE = SITE_DIR / "cert.pem"
KEY_FILE  = SITE_DIR / "key.pem"
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

def gerar_certificado():
    if CERT_FILE.exists() and KEY_FILE.exists():
        print("  ✔  Certificado existente encontrado.")
        return

    print("  ⚙  A gerar certificado SSL auto-assinado...")
    local_ip = get_local_ip()

    san_conf = SITE_DIR / "san.cnf"
    san_conf.write_text(f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = NexoVault Local

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = {local_ip}
IP.2 = 127.0.0.1
DNS.1 = localhost
""")

    result = subprocess.run([
        "openssl", "req", "-x509", "-nodes",
        "-newkey", "rsa:2048",
        "-keyout", str(KEY_FILE),
        "-out",    str(CERT_FILE),
        "-days",   "365",
        "-config", str(san_conf),
        "-extensions", "v3_req"
    ], capture_output=True, text=True)

    san_conf.unlink()

    if result.returncode != 0:
        print("  ✘  Erro ao gerar certificado:")
        print(result.stderr)
        sys.exit(1)

    print("  ✔  Certificado gerado: cert.pem + key.pem")

# ========== INICIALIZA BASE DE DADOS SQLITE ==========
def init_db():
    """Cria base de dados SQLite com utilizadores para SQLi"""
    db_path = SITE_DIR / "users.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER, username TEXT, password TEXT)''')
    c.execute("DELETE FROM users")  # Limpa dados antigos
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT INTO users VALUES (2, 'pedro', 'pedro123')")
    c.execute("INSERT INTO users VALUES (3, 'root', 'toor')")
    conn.commit()
    conn.close()
    print("  ✔  Base de dados SQLite criada: users.db")

# ========== HANDLER COM SQLi ==========
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SITE_DIR), **kwargs)

    def do_GET(self):
        # ===== ROTA SQLi =====
        if self.path.startswith('/vuln'):
            try:
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                user = params.get('user', [''])[0]

                # VULNERÁVEL: concatenação direta de SQL
                db_path = SITE_DIR / "users.db"
                conn = sqlite3.connect(str(db_path))
                c = conn.cursor()
                sql = f"SELECT * FROM users WHERE username = '{user}'"
                c.execute(sql)
                rows = c.fetchall()
                conn.close()

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()

                if rows:
                    response = "<br>".join([f"{row[1]} - {row[2]}" for row in rows])
                else:
                    response = "Nenhum utilizador encontrado."

                # Mostra a query para debug (útil para o orquestrador)
                response += f"<br><br><small>Query: {sql}</small>"
                self.wfile.write(response.encode())

            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Erro: {e}".encode())

        # ===== ROTA XSS =====
        elif self.path.startswith('/xss'):
            try:
                parsed = urlparse(self.path)
                params = parse_qs(parsed.query)
                q = params.get('q', [''])[0]

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()

                # VULNERÁVEL: ecoa o input diretamente
                html = f"""
                <html>
                <body>
                    <h1>Resultados para: {q}</h1>
                    <p>Estás a pesquisar por: {q}</p>
                    <a href="/">Voltar</a>
                </body>
                </html>
                """
                self.wfile.write(html.encode())

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Erro: {e}".encode())

        # ===== FICHEIROS ESTÁTICOS =====
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        else:
            super().do_GET()

    def do_POST(self):
        # ===== ROTA DEFACE =====
        if self.path.startswith('/deface'):
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    post_data = self.rfile.read(content_length)
                    with open("index.html", "wb") as f:
                        f.write(post_data)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"DEFACE APLICADO!")
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Sem dados")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Erro: {e}".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, fmt, *args):
        msg = fmt % args
        if "Bad request" in msg or "favicon.ico" in msg:
            return
        addr = self.client_address[0]
        print(f"  [{addr}]  {msg}")

    def log_error(self, fmt, *args):
        msg = fmt % args
        if any(x in msg for x in ("Broken pipe", "Bad request", "ConnectionReset")):
            return
        print(f"  [ERRO]  {msg}")

# ── Main ─────────────────────────────────────────────────────
os.chdir(SITE_DIR)

print()
print("  ╔══════════════════════════════════════════╗")
print("  ║   NexoVault — Servidor HTTPS + SQLi      ║")
print("  ╚══════════════════════════════════════════╝")
print()

gerar_certificado()
init_db()
print()

local_ip = get_local_ip()

with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
    httpd.allow_reuse_address = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"  🌐  Local:    https://localhost:{PORT}")
    print(f"  🌐  Rede:     https://{local_ip}:{PORT}")
    print()
    print("  🔥  ROTAS VULNERÁVEIS:")
    print(f"      SQLi: https://{local_ip}:{PORT}/vuln?user=admin' OR '1'='1")
    print(f"      XSS:  https://{local_ip}:{PORT}/xss?q=<script>alert(1)</script>")
    print()
    print("  ⚠  Certificado auto-assinado — browser vai mostrar aviso.")
    print('     Clicar em "Avançado" → "Continuar para o site" para aceitar.')
    print()
    print("  Pressiona Ctrl+C para parar o servidor.")
    print()

    try:
        webbrowser.open(f"https://localhost:{PORT}")
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print("  Servidor parado. Até logo!")
        print()
