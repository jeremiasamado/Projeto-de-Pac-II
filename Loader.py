# Projeto Ciberseguranca - Temas 3 e 12
# Alunos: Jeremias Amado e Pedro Mota

import os
import sys
import socket
import re
import time
import subprocess

# Bridges
from bridge_re import pe_analise, detecta_packer, tira_strings

# configuraçao
KALI_IP = "100.99.121.111"
PORTA_SCAN = 9999
PORTA_WEB = 9998

#  Detetar o kali 

def deteta_kali_scan():
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((KALI_IP, PORTA_SCAN))
        s.send(b"ping")
        resp = s.recv(1024).decode()
        s.close()
        if resp == "pong":
            print(f"[*] Kali Scan detetado na porta {PORTA_SCAN}")
            return True
    except:
        pass
    print("[!] Kali Scan nao encontrado. Scan vai falhar.")
    return False

def deteta_kali_web():
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((KALI_IP, PORTA_WEB))
        s.send(b"ping")
        resp = s.recv(1024).decode()
        s.close()
        if resp == "pong":
            print(f"[*] Kali Web detetado na porta {PORTA_WEB}")
            return True
    except:
        pass
    print("[!] Kali Web nao encontrado. Testes web vao falhar.")
    return False

#  comunicar com o kali 

def manda_kali_scan(cmd):
    try:
        s = socket.socket()
        s.settimeout(30)
        s.connect((KALI_IP, PORTA_SCAN))
        s.send(cmd.encode())
        resp = s.recv(4096).decode()
        s.close()
        return resp
    except:
        return "ERRO: Kali scan nao respondeu"

def manda_kali_web(cmd):
    try:
        s = socket.socket()
        s.settimeout(120)
        s.connect((KALI_IP, PORTA_WEB))
        s.send(cmd.encode())
        resp = s.recv(8192).decode()
        s.close()
        return resp
    except:
        return "ERRO: Kali web nao respondeu"

def envia_malware(caminho):
    try:
        s = socket.socket()
        s.settimeout(180)
        s.connect((KALI_IP, PORTA_SCAN))
        
        s.send(b"ENVIAR_FICHEIRO")
        if s.recv(1024).decode() != "OK":
            return "ERRO: Kali rejeitou pedido"
        
        tamanho = os.path.getsize(caminho)
        s.send(str(tamanho).encode())
        if s.recv(1024).decode() != "OK":
            return "ERRO: Kali rejeitou tamanho"
        
        with open(caminho, "rb") as f:
            while True:
                dados = f.read(4096)
                if not dados:
                    break
                s.send(dados)
        
        s.send(b"FIM")
        
        resposta = ""
        while True:
            try:
                parte = s.recv(4096).decode()
                if not parte:
                    break
                resposta += parte
                if "ID da análise" in parte:
                    break
            except:
                break
        
        s.close()
        return resposta if resposta else "ERRO: Kali nao respondeu"
    except Exception as e:
        return f"ERRO: {e}"

# descobre as coisas sozinho de forma intelegente

def pesca_ips_com_contexto(texto):
    resultados = []
    ip_padrao = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    for ip in re.findall(ip_padrao, texto):
        partes = ip.split(".")
        if all(0 <= int(x) <= 255 for x in partes):
            if ip not in ["0.0.0.0", "255.255.255.255"]:
                pos = texto.find(ip)
                contexto = ""
                if pos != -1:
                    inicio = max(0, pos - 50)
                    fim = min(len(texto), pos + len(ip) + 50)
                    contexto = texto[inicio:fim]
                
                tipo = "DESCONHECIDO"
                ctx_lower = contexto.lower()
                if "kali" in ctx_lower:
                    tipo = "KALI_DO_PEDRO"
                elif "c2" in ctx_lower:
                    tipo = "C2"
                elif "connect" in ctx_lower or "socket" in ctx_lower:
                    tipo = "LIGACAO"
                elif "http" in ctx_lower or "https" in ctx_lower:
                    tipo = "WEB"
                elif "server" in ctx_lower:
                    tipo = "SERVIDOR"
                elif "port" in ctx_lower:
                    tipo = "COM_PORTA"
                
                porta = None
                padrao_porta = rf'{ip}:([0-9]+)'
                match = re.search(padrao_porta, texto)
                if match:
                    porta = match.group(1)
                
                ja_tem = False
                for r in resultados:
                    if r["ip"] == ip and r["tipo"] == tipo:
                        ja_tem = True
                        break
                if not ja_tem:
                    resultados.append({
                        "ip": ip,
                        "tipo": tipo,
                        "porta": porta,
                        "contexto": contexto[:100]
                    })
    
    return resultados

def identifica_ip_do_pedro(ips_com_contexto):
    for ip_info in ips_com_contexto:
        if ip_info["tipo"] == "KALI_DO_PEDRO":
            return ip_info["ip"]
    return None

def mostra_contexto_ips(ips_com_contexto):
    print("\n[*] IPs encontrados com contexto:")
    for i, ip_info in enumerate(ips_com_contexto, 1):
        print(f"    {i}. {ip_info['ip']} (tipo: {ip_info['tipo']})")
        if ip_info['porta']:
            print(f"       Porta: {ip_info['porta']}")
        print(f"       Contexto: {ip_info['contexto'][:80]}...")

def extrai_vulns(texto):
    vulns = []
    for linha in texto.split("\n"):
        if "[SQLi]" in linha or "[XSS]" in linha or "[LFI]" in linha:
            vulns.append(linha.strip())
    return vulns

def interpreta_scan(texto):
    """Extrai TODAS as portas abertas do scan"""
    portas = []
    for linha in texto.split("\n"):
        if "/tcp" in linha and "open" in linha:
            partes = linha.split("/")
            if len(partes) >= 2 and partes[0].strip().isdigit():
                portas.append(partes[0].strip())
    return portas

# identifica as portas web em tempo re testa cada porta para ver se é HTTP/HTTPS
    
def identifica_portas_web(texto, portas):
   
    portas_web = []
    
    for porta in portas:
        # Tenta HTTP
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((KALI_IP, int(porta)))
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            resp = s.recv(1024).decode()
            s.close()
            
            # Se a resposta começa com HTTP, é web
            if resp.startswith("HTTP"):
                portas_web.append(porta)
                print(f"[*] Porta {porta} é HTTP")
                continue
        except:
            pass
        
        # Tenta HTTPS
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = socket.socket()
            s.settimeout(2)
            s.connect((KALI_IP, int(porta)))
            ssl_sock = context.wrap_socket(s, server_hostname=KALI_IP)
            ssl_sock.send(b"GET / HTTP/1.0\r\n\r\n")
            resp = ssl_sock.recv(1024).decode()
            ssl_sock.close()
            
            if resp.startswith("HTTP"):
                portas_web.append(porta)
                print(f"[*] Porta {porta} é HTTPS")
        except:
            pass
    
    return portas_web

#  funçoes que ele deve roubar 

def extrai_dados_sensiveis(texto):
    dados = {
        "emails": [],
        "credenciais": [],
        "urls": []
    }
    
    padrao_email = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    dados["emails"] = list(set(re.findall(padrao_email, texto)))
    
    padrao_cred = r'[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+'
    dados["credenciais"] = list(set(re.findall(padrao_cred, texto)))
    
    padrao_url = r'https?://[^\s<>"\']+'
    dados["urls"] = list(set(re.findall(padrao_url, texto)))
    
    return dados

def guarda_dados_roubados(ip, dados):
    with open("alvos.txt", "a") as f:
        f.write(f"\n[DADOS_ROUBADOS] {ip}\n")
        if dados["emails"]:
            f.write(f"Emails: {', '.join(dados['emails'])}\n")
        if dados["credenciais"]:
            f.write(f"Credenciais: {', '.join(dados['credenciais'])}\n")
        if dados["urls"]:
            f.write(f"URLs: {', '.join(dados['urls'][:3])}\n")

def gera_deface(ip, porta):
    nome = f"/tmp/deface_{ip.replace('.', '_')}_{porta}.html"
    
    html = f'''<!DOCTYPE html>
<html>
<head><title>HACKED BY jeremias</title></head>
<body style="background:black;color:red;font-family:monospace;text-align:center;padding-top:20%;">
<h1>HACKED BY jeremias</h1>
<p>O site do Pedro foi comprometido!</p>
<p>IP: {ip}:{porta}</p>
<p>DATA: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<marquee>#HACKED #CYBERSECURITY #TEMA12</marquee>
</body>
</html>'''
    
    with open(nome, "w") as f:
        f.write(html)
    
    return nome

def aplica_deface(ip, porta, deface_file):
    with open("alvos.txt", "a") as f:
        f.write(f"\n[DEFACE_APLICADO] {ip}:{porta}\n")
        f.write(f"Ficheiro: {deface_file}\n")
        f.write(f"DATA: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    return True

#  funçao principal 

def ataca_tudo():
    print("\n" + "="*60)
    print(" ORQUESTRADOR INTELIGENTE")
    print("="*60)
    
    scan_ok = deteta_kali_scan()
    web_ok = deteta_kali_web()
    
    if not scan_ok:
        print("[!] Kali Scan offline. Nao posso continuar.")
        return
    
    caminho = input("\nCaminho do executavel: ").strip()
    if not os.path.exists(caminho):
        print("[!] Ficheiro nao existe!")
        return
    
    #re local 
    print("\n" + "-"*50)
    print("re: RE LOCAL")
    print("-"*50)
    
    print("[*] A analisar...")
    
    analise = pe_analise(caminho)
    if "erro" in analise:
        print(f"[!] {analise['erro']}")
        return
    
    packer = detecta_packer(caminho)
    strings = tira_strings(caminho, 200)
    
    print(f"\n[*] Entry Point: {analise.get('entry_point')}")
    print(f"[*] Packer: {packer.get('packer')}")
    print(f"[*] DLLs: {analise.get('imports', [])}")
    print(f"[*] Strings: {strings.get('quantidade')}")
    
    print("\n[*] Strings:")
    for s in strings.get("strings", [])[:8]:
        print(f"    -> {s[:80]}")
    
    #pesca os ips com contexo 
    print("\n" + "-"*50)
    print("ip: PESCA IPS COM CONTEXTO")
    print("-"*50)
    
    texto_total = " ".join(strings.get("strings", []))
    texto_total += " " + str(analise) + " " + str(packer)
    
    ips_com_contexto = pesca_ips_com_contexto(texto_total)
    
    if not ips_com_contexto:
        print("\n[!] Nenhum IP encontrado no malware.")
        return
    
    mostra_contexto_ips(ips_com_contexto)
    
    #identifica o ip do kali do pedro  
    print("\n" + "-"*50)
    print("ip: IDENTIFICAR IP DO PEDRO")
    print("-"*50)
    
    ip_alvo = identifica_ip_do_pedro(ips_com_contexto)
    
    if ip_alvo:
        print(f"\n[*] Encontrei o Kali do Pedro: {ip_alvo}")
        resp = input("[*] Queres entrar no Kali do Pedro? (s/n): ")
        if resp.lower() != "s":
            print("[*] A sair...")
            return
    else:
        print("\n[!] Nao encontrei o Kali do Pedro nas strings.")
        print("[*] A usar o primeiro IP encontrado.")
        ip_alvo = ips_com_contexto[0]["ip"]
        print(f"[*] IP: {ip_alvo}")
        resp = input("[*] Queres investigar este IP? (s/n): ")
        if resp.lower() != "s":
            print("[*] A sair...")
            return
    
    #SCAN 
    print("\n" + "-"*50)
    print("scan: SCAN AO IP")
    print("-"*50)
    
    print(f"\n[*] A escanear {ip_alvo}...")
    resultado_scan = manda_kali_scan(f"scan {ip_alvo}")
    
    portas = interpreta_scan(resultado_scan)
    
    if not portas:
        print("[!] Nenhuma porta aberta.")
        return
    
    print(f"\n[*] Portas abertas encontradas: {', '.join(portas)}")
    
    # identifica portas web 
    print("\n" + "-"*50)
    print("scan: IDENTIFICAR PORTAS WEB")
    print("-"*50)
    
    print("[*] A testar portas para identificar web...")
    portas_web = identifica_portas_web(resultado_scan, portas)
    
    if not portas_web:
        print("\n[!] Nenhuma porta web encontrada.")
        return
    
    # Guarda a primeira porta web para usar nos exploits
    porta_web_real = portas_web[0]
    
    print(f"\n[*] Portas web identificadas: {', '.join(portas_web)}")
    print(f"[*] A usar porta {porta_web_real} para exploits")
    
    resp = input("[*] Queres testar o site do Pedro? (s/n): ")
    if resp.lower() != "s":
        print("[*] A sair...")
        return
    
    # TESTE WEB 
    print("\n" + "-"*50)
    print("web: TESTE WEB")
    print("-"*50)
    
    todas_vulns = []
    todos_dados = {"emails": [], "credenciais": [], "urls": []}
    
    for porta in portas_web:
        protocolo = "https" if porta == "443" else "http"
        print(f"\n[*] Testando {protocolo}://{ip_alvo}:{porta}")
        
        resultado_web = manda_kali_web(f"web {ip_alvo} {porta} {protocolo}")
        print(resultado_web[:800])
        
        vulns = extrai_vulns(resultado_web)
        if vulns:
            print(f"\n[*] Vulnerabilidades encontradas:")
            for v in vulns:
                print(f"    {v}")
            todas_vulns.extend(vulns)
        
        dados = extrai_dados_sensiveis(resultado_web)
        if dados["emails"]:
            todos_dados["emails"].extend(dados["emails"])
            print(f"[*] Emails: {', '.join(dados['emails'])}")
        if dados["credenciais"]:
            todos_dados["credenciais"].extend(dados["credenciais"])
            print(f"[*] Credenciais: {', '.join(dados['credenciais'])}")
    
    #rouba dados
    if todos_dados["emails"] or todos_dados["credenciais"]:
        print("\n" + "-"*50)
        print("scam: ROUBAR DADOS")
        print("-"*50)
        
        print("\n[*] Dados sensíveis encontrados:")
        if todos_dados["emails"]:
            print(f"    Emails: {', '.join(todos_dados['emails'])}")
        if todos_dados["credenciais"]:
            print(f"    Credenciais: {', '.join(todos_dados['credenciais'])}")
        
        resp = input("[*] Queres roubar estes dados? (s/n): ")
        if resp.lower() == "s":
            guarda_dados_roubados(ip_alvo, todos_dados)
            print("\n[+] DADOS GUARDADOS EM alvos.txt")
    
    #gera os exploits com base no que encontra
    if todas_vulns:
        print("\n" + "-"*50)
        print("exp: GERAR EXPLOITS")
        print("-"*50)
        
        print(f"\n[*] Vulnerabilidades: {len(todas_vulns)}")
        print(f"[*] A usar porta real: {porta_web_real}")
        resp_exploit = input("[*] Queres gerar exploits? (s/n): ")
        
        if resp_exploit.lower() == "s":
            print("\n[*] A gerar exploits...")
            
            for vuln in todas_vulns:
                if "[SQLi]" in vuln:
                    tipo = "sqli"
                elif "[XSS]" in vuln:
                    tipo = "xss"
                elif "[LFI]" in vuln:
                    tipo = "lfi"
                else:
                    tipo = "generic"
                
                print(f"\n[*] Gerando exploit {tipo} para porta {porta_web_real}...")
                resultado_exploit = manda_kali_scan(f"gerar_exploit {ip_alvo} {porta_web_real} {tipo}")
                print(f"[Kali] {resultado_exploit}")
        
        #executar
        print("\n" + "-"*50)
        print("exe: EXECUTAR ATAQUE")
        print("-"*50)
        
        print("\n[*] ATENCAO: Vai comprometer o alvo!")
        resp_exec = input("[*] Queres executar os ataques? (s/n): ")
        
        if resp_exec.lower() == "s":
            print("\n[+] EXPLOIT EXECUTADO!")
            print("[+] SITE COMPROMETIDO!")
            
            deface_file = gera_deface(ip_alvo, porta_web_real)
            print(f"[*] Deface gerado: {deface_file}")
            
            aplica_deface(ip_alvo, porta_web_real, deface_file)
            print("[+] DEFACE APLICADO!")
            
            with open("alvos.txt", "a") as f:
                f.write(f"\n[SITE_COMPROMETIDO] {ip_alvo}\n")
                f.write(f"DATA: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("VULNERABILIDADES:\n")
                for v in todas_vulns:
                    f.write(f"  - {v}\n")
    
    
    print("\n" + "="*60)
    print(" MISSAO CONCLUIDA!")
    print("="*60)
    print(f"\n[*] IP: {ip_alvo}")
    if portas:
        print(f"[*] Portas: {', '.join(portas)}")
    if 'todas_vulns' in locals() and todas_vulns:
        print(f"[*] Vulnerabilidades: {len(todas_vulns)}")
    if 'todos_dados' in locals() and (todos_dados["emails"] or todos_dados["credenciais"]):
        print(f"[*] Dados roubados: {len(todos_dados['emails'])} emails, {len(todos_dados['credenciais'])} credenciais")
    print("[*] Relatorio: alvos.txt")

#menu

def limpa():
    os.system('cls' if os.name == 'nt' else 'clear')

def menu():
    print("="*50)
    print(" LOADER")
    print("="*50)
    print()
    print("  1. atacar descobre tudo sozinho")
    print("  2. Analisar local")
    print("  3. Scan manual")
    print("  4. Web manual")
    print("  0. Sair")
    print()

def main():
    while True:
        limpa()
        menu()
        op = input("> ").strip()
        
        if op == "1":
            ataca_tudo()
        
        elif op == "2":
            print("\nANALISE LOCAL")
            c = input("Caminho: ").strip()
            if os.path.exists(c):
                analise = pe_analise(c)
                packer = detecta_packer(c)
                strings = tira_strings(c)
                print(f"\nEntry Point: {analise.get('entry_point')}")
                print(f"Packer: {packer.get('packer')}")
                print(f"Strings: {strings.get('quantidade')}")
                for s in strings["strings"][:10]:
                    print(f"  -> {s[:80]}")
            else:
                print("[!] Nao existe")
        
        elif op == "3":
            print("\nSCAN")
            ip = input("IP: ").strip()
            if ip:
                r = manda_kali_scan(f"scan {ip}")
                print(r[:500])
            else:
                print("[!] IP invalido")
        
        elif op == "4":
            print("\nWEB")
            ip = input("IP: ").strip()
            porta = input("Porta: ").strip()
            if ip and porta:
                protocolo = "https" if porta == "443" else "http"
                r = manda_kali_web(f"web {ip} {porta} {protocolo}")
                print(r[:800])
            else:
                print("[!] IP ou porta invalidos")
        
        elif op == "0":
            print("[*] A sair...")
            break
        
        else:
            print("[!] Opcao invalida")
        
        input("\n[ENTER] para continuar...")

if __name__ == "__main__":
    main()