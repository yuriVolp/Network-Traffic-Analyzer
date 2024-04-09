# Network Traffic Analyzer
Este é um programa Python para análise de tráfego de rede usando a biblioteca Scapy. Ele fornece funcionalidades para monitorar o tráfego de rede em tempo real, detectar possíveis ataques DDoS e varreduras de portas, bem como escanear portas em um determinado host.

## Requisitos
Python 3.x
Scapy

## Utilização
python analyzer.py [-h] [-i INTERFACE] [-c COUNT] [-f FILE] [-F FILTER] [-o OUTPUT] [-v] [-t TARGET]

### Argumentos:
-i INTERFACE, --interface INTERFACE: Especifica a interface de rede para capturar pacotes (padrão: eth0).
-c COUNT, --count COUNT: Número de pacotes para capturar.
-f FILE, --file FILE: Arquivo PCAP para analisar.
-F FILTER, --filter FILTER: Filtro BPF para aplicar (por exemplo, 'tcp', 'udp').
-o OUTPUT, --output OUTPUT: Arquivo de saída para salvar os resultados.
-v, --verbose: Ativa a análise detalhada.
-t TARGET, --target TARGET: Endereço IP alvo para escanear portas.

## Funcionalidades
Monitoramento em Tempo Real: O programa monitora o tráfego de rede em tempo real e exibe informações sobre os pacotes capturados, incluindo protocolos, portas de origem e destino e endereços IP.
Detecção de Ataques DDoS: Ele detecta possíveis ataques de negação de serviço (DDoS) monitorando a taxa de pacotes recebidos.
Varredura de Portas: O programa pode escanear portas em um determinado host para verificar quais portas estão abertas.
Análise Detalhada: A opção verbose permite uma análise mais detalhada dos pacotes capturados.
