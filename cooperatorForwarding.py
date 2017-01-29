from scapy.all import *

def resend(pkt, ip_dst):
    if IP in pkt and pkt[IP].tos == 0xff:
        pkt[IP].dst = ip_dst
        pkt[IP].tos = 0
        del pkt[IP].chksum
        pkt = IP(str(pkt[IP])[0:pkt[IP].len])
        send(pkt, loop=0, count=1)
sniff(filter='dst host 10.2.0.1', prn=lambda x: resend(x, '10.1.0.1'))
