#!/usr/bin/env python3
"""
Scanner de Portas TCP/UDP Simples

Funcionalidades:
- Varredura básica de portas TCP e UDP
- Exportação de resultados em arquivo .txt
- Fácil de usar e entender
"""

import socket
import concurrent.futures
from scapy.all import IP, TCP, UDP, sr1, send
import argparse
from datetime import datetime

def verifica_porta_tcp(ip, porta):
    """Verifica se uma porta TCP está aberta usando SYN scan"""
    try:
        pacote = IP(dst=ip)/TCP(dport=porta, flags="S")
        resposta = sr1(pacote, timeout=1, verbose=0)
        
        if resposta and resposta.haslayer(TCP):
            if resposta.getlayer(TCP).flags == 0x12:  # SYN-ACK
                send(IP(dst=ip)/TCP(dport=porta, flags="R"), verbose=0)  # Fecha conexão
                return porta, "ABERTA"
            elif resposta.getlayer(TCP).flags == 0x14:  # RST-ACK
                return porta, "FECHADA"
        return porta, "FILTRADA"
    except:
        return porta, "ERRO"

def verifica_porta_udp(ip, porta):
    """Verifica se uma porta UDP está aberta"""
    try:
        pacote = IP(dst=ip)/UDP(dport=porta)/b"\x00"
        resposta = sr1(pacote, timeout=1, verbose=0)
        
        if resposta:
            if resposta.haslayer(UDP):
                return porta, "ABERTA"
            elif resposta.haslayer(ICMP):
                return porta, "FILTRADA"
        return porta, "ABERTA|FILTRADA"
    except:
        return porta, "ERRO"

def converte_intervalo_portas(portas_str):
    """Converte string '1-100,200,300-400' em lista de portas"""
    portas = set()
    for parte in portas_str.split(','):
        if '-' in parte:
            inicio, fim = map(int, parte.split('-'))
            portas.update(range(inicio, fim + 1))
        else:
            portas.add(int(parte))
    return sorted(portas)

def executa_scan(ip, portas, protocolo):
    """Executa o scan nas portas especificadas"""
    print(f"\n[*] Scan {protocolo} iniciado em {ip} para {len(portas)} portas...")
    
    funcao_scan = verifica_porta_tcp if protocolo == "tcp" else verifica_porta_udp
    resultados = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(funcao_scan, ip, porta): porta for porta in portas}
        for future in concurrent.futures.as_completed(futures):
            porta, status = future.result()
            resultados[porta] = status
    
    return resultados

def salva_resultados(ip, protocolo, resultados):
    """Salva os resultados em um arquivo .txt"""
    nome_arquivo = f"scan_{ip}_{protocolo}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    with open(nome_arquivo, 'w') as arquivo:
        arquivo.write(f"Resultado do scan {protocolo.upper()} em {ip}\n")
        arquivo.write("="*40 + "\n")
        for porta, status in sorted(resultados.items()):
            arquivo.write(f"Porta {porta}: {status}\n")
    
    print(f"[+] Resultados salvos em {nome_arquivo}")

def main():
    # Configura os argumentos do programa
    parser = argparse.ArgumentParser(description="Scanner de Portas TCP/UDP Simples")
    parser.add_argument("ip", help="IP ou domínio do alvo")
    parser.add_argument("-p", "--portas", default="1-1024", help="Portas para scanear (ex: '1-100,443')")
    parser.add_argument("-t", "--tcp", action="store_true", help="Scanear portas TCP")
    parser.add_argument("-u", "--udp", action="store_true", help="Scanear portas UDP")
    
    args = parser.parse_args()
    
    # Verifica se pelo menos um protocolo foi selecionado
    if not args.tcp and not args.udp:
        print("[!] Selecione TCP (-t) e/ou UDP (-u)")
        return
    
    try:
        # Converte o alvo para IP (caso seja um domínio)
        ip_alvo = socket.gethostbyname(args.ip)
    except:
        print(f"[!] Não foi possível resolver {args.ip}")
        return
    
    # Converte a string de portas para lista
    try:
        portas = converte_intervalo_portas(args.portas)
    except:
        print("[!] Formato de portas inválido. Use como '1-100' ou '80,443,8080'")
        return
    
    # Executa os scans solicitados
    if args.tcp:
        resultados_tcp = executa_scan(ip_alvo, portas, "tcp")
        print("\n[+] Resultados TCP:")
        for porta, status in sorted(resultados_tcp.items()):
            print(f"Porta {porta}: {status}")
        salva_resultados(ip_alvo, "tcp", resultados_tcp)
    
    if args.udp:
        resultados_udp = executa_scan(ip_alvo, portas, "udp")
        print("\n[+] Resultados UDP:")
        for porta, status in sorted(resultados_udp.items()):
            print(f"Porta {porta}: {status}")
        salva_resultados(ip_alvo, "udp", resultados_udp)

if __name__ == "__main__":
    print("\n=== Scanner de Portas Simples ===")
    main()