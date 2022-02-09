from scapy.all import *
from subprocess import *
import os


print('Try to flood me on '+get_if_addr(conf.iface))
My_IP = get_if_addr(conf.iface)


while(True):
    
    ICMP_SRC_IP = {}
    ICMP_Packets = sniff(iface = 'enp0s3',filter = 'icmp',timeout =5)

    for packet in ICMP_Packets:
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in ICMP_SRC_IP :
                ICMP_SRC_IP[packet.getlayer(IP).src]+=1
            else :
                ICMP_SRC_IP[packet.getlayer(IP).src]=1
            if ICMP_SRC_IP[packet.getlayer(IP).src]>4 and packet.getlayer(IP).src != My_IP:
                print("This ip "+ packet.getlayer(IP).src+" tried an ICMP attack and was stopped")
                Line = 'sudo iptables -A INPUT -s '+packet.getlayer(IP).src+' -p '+'icmp'+' -j DROP'
                os.popen(Line)
                Line = 'sudo iptables-save'
                os.popen(Line)
                Line = ''
                ICMP_SRC_IP[packet.getlayer(IP).src] = 0
