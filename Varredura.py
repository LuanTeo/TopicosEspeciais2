import socket
import concurrent.futures
# importando os pacotes neceários

def scan_tcp_port(ip, port):
    # fazemos o scan de uma porta TCP utilizando pacotes SYN
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            # envio de pacotes
            sock.connect((ip, port))
            return port, "Aberta"
        except (socket.timeout, ConnectionRefusedError):
            return port, "Fechada"
        except socket.error:
            return port, "Fechada"

def scan_udp_port(ip, port):
    # scan de uma porta UDP com sondagem
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            # enviando um pacote de imitação para sondar a porta UDP
            sock.sendto(b'\x00', (ip, port))
            sock.recvfrom(1024)  
            return port, "Aberta"
        except socket.timeout:
            return port, "Filtrada"
        except ConnectionRefusedError:
            return port, "Fechada"
        except socket.error:
            return port, "Fechada"

def scan_ports(ip, ports, protocolo="tcp"):
    # faz o scan de várias portas para um determinado protocolo
    scanner = scan_tcp_port if protocolo.lower() == "tcp" else scan_udp_port
    resultados = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scanner, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port, status = future.result()
            resultados[port] = status
    return resultados

# recebe os dados do usuário
target_ip = input("Digite o IP de destino: ")
start_port = int(input("Porta inicial: "))
end_port = int(input("Porta final: "))
protocolo = input("Protocolo (TCP/UDP): ").strip().lower()

# Intervalo de portas
ports = range(start_port, end_port + 1)

# faz a varredura
resultados = scan_ports(target_ip, ports, protocolo)

print("\nResultados da varredura:")
for port, status in resultados.items():
    print(f"Porta {port}: {status}")


# Comando para executar no terminal linux - sudo python3 Varredura.py
# Luan Mateus - Maria Julia 