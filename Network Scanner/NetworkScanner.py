import scapy.all as scapy



def scan(ip):
    arp_request= scapy.ARP(pdst=ip)
 
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
 
    arp_broadcast= brodcast/arp_request

    answerd= scapy.srp(arp_broadcast,timeout=1)[0]
 

    for i in answerd:
        print(i[1].psrc)
        print(i[1].hwsrc)
        print('---------------')
    

scan("192.168.31.1/24")

