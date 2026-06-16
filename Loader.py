# Projeto Ciberseguranca - Temas 3 e 12
# Alunos: Jeremias Amado e Pedro Mota
# Este ficheiro e o menu principal que orquestra os bridges

import os
import sys
import socket
import re

# o nosso bridge de RE 
from bridge_re import pe_analise, detecta_packer, tira_strings

# ip e porta do kali do Pedro
KALI_IP = ""
KALI_PORTA = ""

def deteta_kali_automatico():
    # tenta encontrar o bridge_scan do pedro na rede local
    
    ips_teste = ["192.168.1.50", "192.168.1.100", "10.0.0.5", "127.0.0.1"]
    porta_teste = 9999
    
    for ip in ips_teste:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, porta_teste))
            s.send(b"ping")
            resp = s.recv(1024).decode()
            s.close()
            if resp == "pong":
                print(f"[*] Kali do Pedro detetado em {ip}:{porta_teste}")
                return ip, porta_teste
        except:
            continue
    
    print("[!] Kali do pedro nao encontrado. Algumas opcoes vao falhar.")
    return None, None

def mandar_pro_kali(comando):    
    try:
        s = socket.socket()
        s.settimeout(8)
        s.connect((KALI_IP, KALI_PORTA))
        s.send(comando.encode())
        resp = s.recv(4096).decode()
        s.close()
        return resp
    except:
        return "Erro: Kali nao respondeu. O bridge_scan.py esta a correr?"

def mandar_ficheiro_pro_kali(caminho_ficheiro):
    # isto envia o malware para o kali e pede para analisar
    try:
        s = socket.socket()
        s.settimeout(60)
        s.connect((KALI_IP, KALI_PORTA))
        
        s.send(b"ENVIAR_FICHEIRO")
        s.recv(1024)
        
        tamanho = os.path.getsize(caminho_ficheiro)
        s.send(str(tamanho).encode())
        s.recv(1024)
        
        with open(caminho_ficheiro, "rb") as f:
            while True:
                dados = f.read(4096)
                if not dados:
                    break
                s.send(dados)
        
        s.send(b"FIM")
        
        resultado = s.recv(4096).decode()
        s.close()
        return resultado
    except Exception as e:
        return f"ERRO: {str(e)}"

def limpa():
    os.system('cls' if os.name == 'nt' else 'clear')

def menu():
    print("LOADER")
    print()
    print("Reverse Engineering:")
    print("  1. Analisar executavel (PE)")
    print("  2. Detetar packer")
    print("  3. Extrair strings")
    print()
    print("Network Scanning:")
    print("  4. Scan de portas (via Kali)")
    print("  5. Detetar WAF (via Kali)")
    print()
    print("  7. PIPELINE COMPLETO (RE + Scan)")
    print()
    print("  0. Sair")
    print()

def interpreta_resultados(analise, packer, strings):
    # funcao que interpreta os resultados sem regras fixas
    # devolve o que encontrou e sugestoes
    
    encontrado = {
        "ips": [],
        "portas": [],
        "palavras_sensiveis": [],
        "packers": [],
        "sugestoes": []
    }
    
    # olha para as strings
    for s in strings.get("strings", []):
        # procura por ip (qualquer coisa com 3 ou 4 pontos)
        if s.count(".") >= 3 and len(s) < 20:
            # tenta ver se parece ip
            partes = s.split(".")
            if len(partes) == 4:
                tudo_numero = True
                for p in partes:
                    if not p.isdigit():
                        tudo_numero = False
                        break
                if tudo_numero:
                    if s not in encontrado["ips"]:
                        encontrado["ips"].append(s)
        
        # ve se é porta
        if s.isdigit():
            num = int(s)
            if num > 0 and num < 65536:
                if s not in encontrado["portas"]:
                    encontrado["portas"].append(s)
        
        # procura emails (coisa com @)
        if "@" in s and "." in s and len(s) < 50:
            if s not in encontrado["palavras_sensiveis"]:
                encontrado["palavras_sensiveis"].append(s[:50])
        
        # procura URLs (coisa com http ou https)
        if "http" in s.lower() and len(s) < 100:
            if s not in encontrado["palavras_sensiveis"]:
                encontrado["palavras_sensiveis"].append(s[:50])
        
        # procura caminhos do Windows (coisa com C:\)
        if "C:\\" in s or "c:\\" in s:
            if s not in encontrado["palavras_sensiveis"]:
                encontrado["palavras_sensiveis"].append(s[:50])
        
        # ve se é palavra suspeita (qualquer coisa que nao seja numero)
        if len(s) >= 4 and len(s) <= 25:
            if not s.isdigit():
                if s not in encontrado["palavras_sensiveis"]:
                    encontrado["palavras_sensiveis"].append(s[:50])
    
    # olha para o packer
    if "upx" in packer.get("info", "").lower():
        encontrado["packers"].append("UPX")
        encontrado["sugestoes"].append("UPX detectado. Pode descomprimir com upx -d")
    if "vmprotect" in packer.get("info", "").lower():
        encontrado["packers"].append("VMProtect")
        encontrado["sugestoes"].append("VMProtect detectado. Dificil de reverter")
    if "themida" in packer.get("info", "").lower():
        encontrado["packers"].append("Themida")
        encontrado["sugestoes"].append("Themida detectado. Anti-debug ativo")
    
    return encontrado

def interpreta_scan(resultado_scan):
    # interpreta o resultado do scan sem regras fixas
    portas_encontradas = []
    
    linhas = resultado_scan.split("\n")
    for linha in linhas:
        # procura por "porta/tcp" ou "porta/udp"
        if "/tcp" in linha or "/udp" in linha:
            # tenta extrair o numero da porta
            partes = linha.split("/")
            if len(partes) >= 2:
                porta_str = partes[0].strip()
                if porta_str.isdigit():
                    portas_encontradas.append(porta_str)
    
    return portas_encontradas

def tema3_pipeline():
    print("REVERSE ENGINEERING")
    caminho = input("Caminho do executavel: ").strip()

    if not os.path.exists(caminho):
        print("Erro: ficheiro nao encontrado!")
        return

    print()
    print("[*] Alvo:", caminho)

    # analise pe
    print()
    print("[1/3] Analise estatica do PE...")
    analise = pe_analise(caminho)
    if "erro" in analise:
        print("Erro:", analise["erro"])
        return

    print("  Entry Point:", analise.get("entry_point"))
    print("  Seccoes:", analise.get("seccoes"))
    print("  DLLs:", analise.get("imports", []))
    print("  Tamanho:", analise.get("tamanho", 0), "bytes")

    # packer 
    print()
    print("[2/3] Detecao de packer...")
    packer = detecta_packer(caminho)
    print("  Packer:", packer.get("packer"))
    print("  Info:", packer.get("info"))

    # strings
    print()
    print("[3/3] Extrair strings...")
    strings = tira_strings(caminho)
    print("  Encontradas:", strings.get("quantidade"))
    for s in strings.get("strings", [])[:10]:
        print("    ->", s[:80])

    # interpreta os resultados
    print()
    print("[*] LOADER A INTERPRETAR RESULTADOS...")
    
    interpretado = interpreta_resultados(analise, packer, strings)
    
    print(f"[*] IPs encontrados: {interpretado['ips'] if interpretado['ips'] else 'Nenhum'}")
    print(f"[*] Portas encontradas: {interpretado['portas'] if interpretado['portas'] else 'Nenhuma'}")
    print(f"[*] Palavras sensiveis: {len(interpretado['palavras_sensiveis'])}")
    print(f"[*] Packers sugeridos: {interpretado['packers'] if interpretado['packers'] else 'Nenhum'}")
    
    for sugestao in interpretado["sugestoes"]:
        print(f"[!] Sugestao: {sugestao}")
    
    # decide o que fazer baseado no que encontrou
    print()
    print("[*] LOADER A DECIDIR PROXIMO PASSO...")
    
    if interpretado["ips"] and KALI_IP:
        ip_alvo = interpretado["ips"][0]
        print(f"[*] LOADER: Encontrei um IP: {ip_alvo}")
        print("[*] LOADER: Recomendo fazer scan a este IP.")
        resp = input("   Autoriza o scan? (s/n): ")
        
        if resp.lower() == "s":
            print()
            print("[*] A escanear...")
            resultado_scan = mandar_pro_kali(f"scan {ip_alvo}")
            print(resultado_scan[:500])
            
            with open("alvos.txt", "a") as f:
                f.write(f"\n[SCAN] {ip_alvo}\n")
                f.write(resultado_scan[:500])
            
            # interpreta o resultado do scan
            print()
            print("[*] LOADER: A interpretar resultados do scan...")
            portas_scan = interpreta_scan(resultado_scan)
            
            if portas_scan:
                print(f"[*] LOADER: Portas encontradas: {portas_scan}")
                print("[*] LOADER: Recomendo enviar malware para Kali para analise profunda.")
                resp2 = input("   Autoriza envio para Kali? (s/n): ")
                
                if resp2.lower() == "s":
                    print("[*] A enviar ficheiro...")
                    resultado_kali = mandar_ficheiro_pro_kali(caminho)
                    print(f"[Kali] {resultado_kali[:500]}")
                    
                    with open("alvos.txt", "a") as f:
                        f.write(f"\n[KALI_ANALISE] {caminho}\n")
                        f.write(resultado_kali[:500])
                    
                    # pergunta se quer gerar exploit
                    print()
                    print("[*] LOADER: Quer gerar exploit para as portas que encontrei?")
                    resp3 = input("   (s/n): ")
                    
                    if resp3 == "s" or resp3 == "S":
                        for porta in portas_scan:
                            print(f"[*] A gerar exploit para porta {porta}...")
                            res = mandar_pro_kali(f"gerar_exploit {ip_alvo} {porta}")
                            print(res)
                            
                            # guarda no ficheiro
                            with open("alvos.txt", "a") as f:
                                f.write(f"\n[EXPLOIT] {ip_alvo}:{porta}\n")
                                f.write(res)
            else:
                print("[*] LOADER: Nenhuma porta encontrada no scan.")
    
    else:
        if not interpretado["ips"]:
            print("[*] LOADER: Nao consegui encontrar nada util na analise local.")
            print("[*] LOADER: Vou para o Kali fazer analise profunda com Radare2...")
            print("[*] LOADER: Fica ai a ver que eu faco o trabalho.")
            
            if KALI_IP:
                # manda automaticamente sem perguntar
                resultado_kali = mandar_ficheiro_pro_kali(caminho)
                print(f"\n[Kali] Resultado do Radare2:\n{resultado_kali[:500]}")
                
                # tenta extrair IPs e portas do resultado do Kali
                # converte o resultado em strings para interpretar
                strings_do_kali = {"strings": resultado_kali.split()}
                kali_interpretado = interpreta_resultados(analise, packer, strings_do_kali)
                
                if kali_interpretado["ips"]:
                    interpretado["ips"] = kali_interpretado["ips"]
                    print(f"[*] LOADER: Radare2 encontrou IP: {kali_interpretado['ips'][0]}")
                if kali_interpretado["portas"]:
                    interpretado["portas"] = kali_interpretado["portas"]
                    print(f"[*] LOADER: Radare2 encontrou portas: {kali_interpretado['portas']}")
                
                # se conseguiu encontrar algo, continua para o scan
                if interpretado["ips"]:
                    ip_alvo = interpretado["ips"][0]
                    print(f"\n[*] LOADER: IP alvo: {ip_alvo}")
                    print("[*] LOADER: Recomendo fazer scan a este IP.")
                    resp = input("   Autoriza o scan? (s/n): ")
                    
                    if resp.lower() == "s":
                        print()
                        print("[*] A escanear...")
                        resultado_scan = mandar_pro_kali(f"scan {ip_alvo}")
                        print(resultado_scan[:500])
                        
                        with open("alvos.txt", "a") as f:
                            f.write(f"\n[SCAN] {ip_alvo}\n")
                            f.write(resultado_scan[:500])
                        
                        print()
                        print("[*] LOADER: A interpretar resultados do scan...")
                        portas_scan = interpreta_scan(resultado_scan)
                        
                        if portas_scan:
                            print(f"[*] LOADER: Portas encontradas: {portas_scan}")
                            print("[*] LOADER: Quer gerar exploit para as portas que encontrei?")
                            resp2 = input("   (s/n): ")
                            
                            if resp2 == "s" or resp2 == "S":
                                for porta in portas_scan:
                                    print(f"[*] A gerar exploit para porta {porta}...")
                                    res = mandar_pro_kali(f"gerar_exploit {ip_alvo} {porta}")
                                    print(res)
                                    
                                    with open("alvos.txt", "a") as f:
                                        f.write(f"\n[EXPLOIT] {ip_alvo}:{porta}\n")
                                        f.write(res)
                        else:
                            print("[*] LOADER: Nenhuma porta encontrada no scan.")
            else:
                print("[*] LOADER: Kali offline. Nao e possivel continuar.")
        else:
            if not KALI_IP:
                print("[*] LOADER: Kali offline. Nao e possivel continuar.")
    
    # guarda tudo no alvos.txt (so no final)
    with open("alvos.txt", "a") as f:
        f.write(f"\n[RE_ANALISE] {caminho}\n")
        f.write(f"Packer: {packer.get('packer')}\n")
        f.write(f"Strings: {strings.get('quantidade')}\n")
        f.write(f"IPs encontrados: {interpretado['ips']}\n")
        f.write(f"Portas encontradas: {interpretado['portas']}\n")
    
    print()
    print("[+] Tema 3 concluido!")

def tema12_pipeline():
    print("NETWORK SCANNING")
    ip = input("IP ou dominio alvo: ").strip()

    if not ip:
        print("Erro: alvo invalido!")
        return

    print()
    print("[*] Alvo:", ip)

    print()
    print("[1/2] Scan de portas (via Kali)...")
    resp = mandar_pro_kali(f"scan {ip}")
    print(resp[:500])

    print()
    print("[2/2] Detecao de WAF (via Kali)...")
    resp = mandar_pro_kali(f"waf {ip}")
    print(resp[:500])

    print()
    print("SUGESTOES DE BYPASS")
    print("  -> Verificar portas abertas para servicos vulneraveis.")
    print("  -> Se WAF detectado, usar tecnicas de evasao.")
    print("  -> Testar credenciais default em servicos como SSH e FTP.")

    print()
    print("[+] Tema 12 concluido!")

def pipeline_completo():
    print("PIPELINE AUTOMATICO")

    print()
    print(">>> FASE 1: REVERSE ENGINEERING <<<")
    tema3_pipeline()

    print()
    print(">>> FASE 2: NETWORK SCANNING <<<")
    tema12_pipeline()

    print()
    print("[+] Pipeline concluido! Ver relatorio para mais detalhes.")

def main():
    
    global KALI_IP, KALI_PORTA
    
    kali_ip, kali_porta = deteta_kali_automatico()
    if kali_ip:
        KALI_IP = kali_ip
        KALI_PORTA = kali_porta
    
    while True:
        limpa()
        menu()
        op = input("> ").strip()

        if op == "1":
            tema3_pipeline()

        elif op == "2":
            print("DETECAO DE PACKER")
            c = input("Caminho do executavel: ").strip()
            if os.path.exists(c):
                p = detecta_packer(c)
                print()
                print("Packer:", p["packer"])
                print("Info:", p["info"])
            else:
                print("Erro: ficheiro nao existe!")

        elif op == "3":
            print("EXTRACAO DE STRINGS")
            c = input("Caminho do executavel: ").strip()
            if os.path.exists(c):
                s = tira_strings(c)
                print()
                print("Strings encontradas:", s["quantidade"])
                for st in s["strings"][:10]:
                    print("  ->", st[:80])
            else:
                print("Erro: ficheiro nao existe!")

        elif op == "4":
            print("SCAN DE PORTAS")
            ip = input("IP ou dominio: ").strip()
            if ip:
                resp = mandar_pro_kali(f"scan {ip}")
                print(resp[:500])
            else:
                print("Erro: IP invalido!")

        elif op == "5":
            print("DETECAO DE WAF")
            ip = input("IP ou dominio: ").strip()
            if ip:
                resp = mandar_pro_kali(f"waf {ip}")
                print(resp[:500])
            else:
                print("Erro: IP invalido!")

        elif op == "7":
            pipeline_completo()

        elif op == "0":
            print("[*] A sair...")
            break

        else:
            print("Opcao invalida!")

        input("\n[ENTER] para continuar...")

if __name__ == "__main__":
    main()