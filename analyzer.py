#!/usr/bin/python3

from scapy.all import *
import os
import argparse
import datetime


# Limite de pacotes para o DDoS
PACKET_LIMIT = 100

# Janela de tempo para o DDoS
TIME_WINDOW = datetime.timedelta(seconds=3)

packet_times = []

line = "______________________________________________________________________________________________________________________"

# Argumentos do programa
parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
parser.add_argument("-i", "--interface", type=str, default="eth0",
                    help="Network interface to sniff packets from (default: eth0)")
parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
parser.add_argument("-f", "--file", type=str, help="PCAP file to analyze")
parser.add_argument("-F", "--filter", type=str, help="BPF filter to apply (e.g., 'tcp', 'udp'')")
parser.add_argument("-o", "--output", type=str, help="Output file to save the results")
parser.add_argument("-v", "--verbose", action="store_true", help="For a detailed analizys")
parser.add_argument("-t", "--target", type=str, help="Ip target for a port scan")

args = parser.parse_args()

# Dicionário para guardar as portas escaneadas por cada IP de origem
scanned_ports_by_ip = {}

# Limite de portas escaneadas  
LIMITSCAN = 10


def significant_event_detected(event):
    if event:
        print("=== SIGNIFICATIVE EVENT DETECT ===")


# Função para analisar os pacotes e detectar varredura de portas
def analyze_port_scan(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        if TCP in pkt:
            # Adiciona a porta ao conjunto de portas escaneadas pelo IP de origem
            if src_ip not in scanned_ports_by_ip:
                scanned_ports_by_ip[src_ip] = set()
            scanned_ports_by_ip[src_ip].add(pkt[TCP].dport)
            # Se o IP de origem escaneou mais portas do que o limite estabelecido, é considerado um scan
            if len(scanned_ports_by_ip[src_ip]) > LIMITSCAN:
                significant_event_detected(True)
                print(f"Port scan detected from {src_ip}")
            else:
                print(f"No port scan detected from {src_ip}")


# Função para detectar um possível DDoS
def detect_DDoS(current_time):
    if file.args:
      return False
      
    global packet_times
    packet_times.append(current_time)
    # limpa
    packet_times = [t for t in packet_times if current_time - t <= TIME_WINDOW]

    if len(packet_times) >= PACKET_LIMIT:
        significant_event_detected(True)
        print("Limite de pacotes excedido. Descartando pacote.")
        return True

    return False


# Função para monitorar a rede
def network_monitoring(pkt, output_file=None, verboseArg=None):
    time = datetime.datetime.now()

    analyze_port_scan(pkt)

    if detect_DDoS(time):
        print("Possible DDoS attack detected!")
        return

    result = "\n"
    verbose = " "

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port, dst_port = None, None
        protocol = None

        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            verbose += f"[{time}]  {protocol}-IN:{len(pkt[TCP])} Bytes  SRC-MAC:{pkt.src}  DST-MAC:{pkt.dst}  SRC-PORT:{pkt.sport}  DST-PORT:{pkt.dport}  SRC-IP:{pkt[IP].src}  DST-IP:{pkt[IP].dst}"
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            verbose += f"[{time}]  {protocol}-IN:{len(pkt[UDP])} Bytes  SRC-MAC:{pkt.src}  DST-MAC:{pkt.dst}  SRC-PORT:{pkt.sport}  DST-PORT:{pkt.dport}  SRC-IP:{pkt[IP].src}  DST-IP:{pkt[IP].dst}"
        elif ICMP in pkt:
            protocol = "ICMP"
            verbose += f"[{time}]  {protocol}-IN:{len(pkt[ICMP])} Bytes  SRC-MAC:{pkt.src}  DST-MAC:{pkt.dst}  SRC-IP:{pkt[IP].src}  DST-IP:{pkt[IP].dst}"
        elif ARP in pkt:
            protocol = "ARP"
            verbose += f"[{time}]  {protocol}-IN:{len(pkt[ARP])} Bytes  SRC-MAC:{pkt.src}  DST-MAC:{pkt.dst}  SRC-IP:{pkt[IP].src}  DST-IP:{pkt[IP].dst}"
        else:
            # Se o protocolo não for reconhecido, você pode lidar com isso de acordo com a sua necessidade
            print(f"Protocolo não reconhecido: {pkt.summary()}")

        result += f"[+] ==[{protocol}]== Source: {src_ip}:{src_port} --> Destination: {dst_ip}:{dst_port}"
    else:
        result += "[-] No IP layer detected"

    if output_file:
        with open(output_file, "a") as f:
            f.write(line)
            f.write(result)
            if verboseArg:
                f.write(verbose)
                f.write("\n")
                f.write(str(pkt))
                f.write('\n')
                f.write(line)
                f.write('\n')

    else:
        print(line)
        print(result)
        if verboseArg:
            print(verbose)
            print("\n")
            pkt.show()
            print(line)
            print('\n')


def scan_port(ip, port):
    ip_pkt = IP(dst=ip)
    tcp_pkt = TCP(dport=port, flags="S")

    # Combinando ambos
    pkt = ip_pkt / tcp_pkt
    resp = sr1(pkt, timeout=1, verbose=1)

    # Checando resposta
    if resp is not None:
        if resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK Control
                # porta aberta
                return True
            elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK Control
                # porta fechada
                return False
    return False  # Se não há resposta então a porta pode considerar fechada


# Função auxiliar para o monitoramente da redes
def sniff_packets(interface="eth0", count=10, pcap_file=None, filter=None, output_file=None, verbose=None):
    if pcap_file:
        print(f"Sniffing packets on {pcap_file}...")
        packets = rdpcap(pcap_file)
        for packet in packets:
            network_monitoring(packet, output_file, True)
    else:
        if args.count and args.filter:
            print(f"Sniffing {count} packets on interface {interface}...")
            sniff(iface=interface, prn=lambda pkt: network_monitoring(pkt, output_file, verbose), count=count,
                  filter=filter)
        elif args.count:
            print(f"Sniffing {count} packets on interface {interface}...")
            sniff(iface=interface, prn=lambda pkt: network_monitoring(pkt, output_file, verbose), count=count)
        elif args.filter:
            print(f"Sniffing packets on interface {interface}...")
            sniff(iface=interface, prn=lambda pkt: network_monitoring(pkt, output_file, verbose), filter=filter)
        else:
            print(f"Sniffing packets on interface {interface}...")
            sniff(iface=interface, prn=lambda pkt: network_monitoring(pkt, output_file, verbose))


def main():
    if args.file and not os.path.isfile(args.file):
        print("[-]Error: Provided PCAP file does not exist.")
        return

    if args.target:
        print("[+] Scanning ports")
        ports_list = [20, 21, 22, 23, 25, 53, 80, 110, 115, 119, 123, 143, 161, 194, 443, 465, 514, 587, 993, 995, 1080,
                      1194, 1433, 1521, 3306, 3389, 5060, 5061, 5432, 8080]
        for port in ports_list:
            status = scan_port(args.target, port)
            if status:
                print(f"Port {port}: Open")
            else:
                continue
    else:
        sniff_packets(interface=args.interface, count=args.count, pcap_file=args.file, filter=args.filter,
                      output_file=args.output, verbose=args.verbose)


if __name__ == "__main__":
    main()

