from scapy.all import *
from subprocess import *
import os


print('Try to flood me on '+get_if_addr(conf.iface))
My_IP = get_if_addr(conf.iface)


while(True):
    
    
    ICMP_Packets = sniff(iface = 'enp0s3',filter = 'icmp',timeout =5)
    ICMP_SRC_IP = {}

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


    
    TCP_Packets = sniff(iface = 'enp0s3',filter = 'tcp',timeout =5)
    TCP_SRC_IP = {}

    for packet in TCP_Packets:
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in TCP_SRC_IP :
                TCP_SRC_IP[packet.getlayer(IP).src]+=1
            else :
                TCP_SRC_IP[packet.getlayer(IP).src]=1
            if TCP_SRC_IP[packet.getlayer(IP).src]>20 and packet.getlayer(IP).src != MY_IP:
                print("This ip "+ packet.getlayer(IP).src+" tried a TCP attack and was stopped")
                
                Line = 'sudo iptables -A INPUT -s '+packet.getlayer(IP).src+' -p '+'tcp'+' -j DROP'
                os.popen(Line)
                Line = 'sudo iptables -save'
                os.popen(Line)
                Line=''
                TCP_SRC_IP[packet.getlayer(IP).src] = 0


    
    UDP_Packets = sniff(iface = 'enp0s3',filter = 'udp',timeout =1)
    UDP_SRC_IP = {}

    for packet in UDP_Packets:
        if (packet.haslayer(IP)):
            if packet.getlayer(IP).src in UDP_SRC_IP :
                UDP_SRC_IP[packet.getlayer(IP).src]+=1
            else :
                UDP_SRC_IP[packet.getlayer(IP).src]=1
            if UDP_SRC_IP[packet.getlayer(IP).src]>25 and packet.getlayer(IP).src != My_IP :
                print("This ip "+ packet.getlayer(IP).src+" tried a UDB attack and was stopped")
                Line = 'sudo iptables -A INPUT -s '+packet.getlayer(IP).src+' -p '+'udp'+' -j DROP'
                os.popen(Line)
                Line = 'sudo iptables-save'
                os.popen(Line)
                Line=''
                UDP_SRC_IP[packet.getlayer(IP).src] = 0


