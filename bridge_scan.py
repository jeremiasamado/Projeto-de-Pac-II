# Bridge de Network Scanning - Tema 12
# Corre no Kali do Pedro recebe comandos do loader.py do jeremias

import socket
import subprocess
import os
import time

PORTA = 9999

def corre_nmap_portas(ip):
    try:
        r = subprocess.run(
            ["nmap", "-F", ip],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout
    except:
        return "Erro ao correr nmap."

def corre_nmap_waf(ip):
    try:
        r = subprocess.run(
            ["nmap", "-p", "80,443", "--script", "http-waf-detect", ip],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout
    except:
        return "Erro ao verificar WAF."

def descomprime_upx(caminho):
    # tenta descomprimir com upx
    try:
        resultado = subprocess.run(
            ["upx", "-d", caminho, "-o", caminho + "_descomp"],
            capture_output=True, text=True, timeout=30
        )
        if resultado.returncode == 0:
            return f"UPX descompressao concluida. Ficheiro: {caminho}_descomp"
        else:
            return f"UPX falhou: {resultado.stderr}"
    except:
        return "Erro ao executar upx"

def analisa_radare2(caminho):
    # analise rapida com radare2
    try:
        r = subprocess.run(
            ["r2", "-A", "-q", "-c", "afl; q", caminho],
            capture_output=True, text=True, timeout=60
        )
        return r.stdout[:1000]
    except:
        return "Erro ao executar radare2"

def gera_exploit_simples(ip, porta, caminho_malware):
    nome = f"/tmp/exploit_{ip.replace('.', '_')}_{porta}.py"

    if porta == 445 or porta == "445":
        tipo = "EternalBlue"
        pay = f'b"\\\\\\\\{ip}\\\\IPC$"'
    elif porta == 22 or porta == "22":
        tipo = "SSH"
        pay = 'b"SSH-2.0-Exploit"'
    elif porta == 80 or porta == 443 or porta == "80" or porta == "443":
        tipo = "Web"
        pay = f'"GET / HTTP/1.1\\r\\nHost: {ip}\\r\\n\\r\\n".encode()'
    else:
        tipo = "Generico"
        pay = 'b"EXPLOIT_PAYLOAD"'

    codigo = f'''# Exploit gerado no Kali
# Alvo: {ip}:{porta}
# Tipo: {tipo}

import socket

s = socket.socket()
s.settimeout(5)
s.connect(("{ip}", {porta}))

payload = {pay}
s.send(payload)
resp = s.recv(1024)
print(resp[:100])
s.close()
'''

    open(nome, "w").write(codigo)
    return f"Exploit gerado: {nome}"

def recebe_ficheiro(conn):
    # recebe ficheiro enviado pelo loader
    try:
        conn.send(b"OK_READY")
        tamanho = int(conn.recv(1024).decode())
        conn.send(b"OK_SIZE")
        
        caminho = f"/tmp/malware_recebido_{int(time.time())}.exe"
        dados_recebidos = 0
        
        with open(caminho, "wb") as f:
            while dados_recebidos < tamanho:
                dados = conn.recv(4096)
                if not dados:
                    break
                f.write(dados)
                dados_recebidos += len(dados)
        
       
        conn.recv(1024)
        
        return caminho
    except Exception as e:
        return f"ERRO: {str(e)}"

def processa(comando, conn=None):
    # processa comandos do loader
    
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
            caminho = recebe_ficheiro(conn)
            if "ERRO" in caminho:
                return caminho
            
            # faz analise basica do ficheiro recebido
            resultado = f"Ficheiro recebido: {caminho}\n"
            resultado += f"Tamanho: {os.path.getsize(caminho)} bytes\n"
            
            # tenta descomprimir se for UPX
            resultado += "\n[1] A testar UPX...\n"
            resultado += descomprime_upx(caminho)
            
            # analise com radare2
            resultado += "\n[2] A analisar com radare2...\n"
            resultado += analisa_radare2(caminho)
            
            # se tiver ip, sugere exploit
            # tenta extrair ip do nome ou de algum lugar
            resultado += "\n[3] Analise concluida.\n"
            resultado += "Sugestao: executar nmap para descobrir portas e depois gerar exploit.\n"
            
            return resultado
        else:
            return "ERRO: Comando enviar_ficheiro sem conexao"
    
    elif comando.startswith("gerar_exploit"):
        # formato: gerar_exploit ip porta
        partes = comando.split(" ")
        if len(partes) >= 3:
            ip = partes[1]
            porta = partes[2]
            return gera_exploit_simples(ip, porta, "")
        else:
            return "ERRO: Uso: gerar_exploit <ip> <porta>"
    
    else:
        return f"Comando desconhecido: {comando}"

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORTA))
    s.listen(1)
    
    print("="*50)
    print("Bridge Scan - Kali do Pedro")
    print(f"A escutar na porta {PORTA}")
    print("Comandos disponiveis: scan, waf, ENVIAR_FICHEIRO, gerar_exploit, ping")
    print("="*50)
    
    while True:
        conn, addr = s.accept()
        print(f"\n[*] Ligacao de {addr[0]}")
        
        comando = conn.recv(4096).decode().strip()
        print(f"[*] Comando: {comando}")
        
        resultado = processa(comando, conn)
        conn.send(resultado.encode()[:4096])
        conn.close()
        
        print("[*] Resposta enviada")

if __name__ == "__main__":
    main()