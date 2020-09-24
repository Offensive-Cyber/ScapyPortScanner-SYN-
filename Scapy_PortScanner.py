import logging
import threading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import *


target = str(input("Please Enter The Target IP: "))
from_port = int(input("From Port: "))
to_port = int(input("To Port: "))
print(f"Scanning {target} for Open TCP Ports\n")

port_list = range(from_port, to_port)

sport = RandShort()

for x in port_list:
    pkt = sr1(IP(dst=target) / TCP(sport=sport, dport=x, flags="S"), timeout=0.5, verbose=0)
    if pkt != None:
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 18:
                print(f"[+] Port {str(x)} Is Open")


print('Scan Is Completed!\n')
