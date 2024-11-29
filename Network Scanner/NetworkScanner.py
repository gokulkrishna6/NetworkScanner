import scapy.all as scapy
from optparse import OptionParser

def network_scan_fun(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    
    client_list = []
    
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_output_fun(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in result_list:
        print(f"{client['ip']}\t\t{client['mac']}")

def parse_options():

    parser = OptionParser(
        usage="usage: %prog -t <target>",
        description="Network Scanner to find devices on the network.",
    )
    parser.add_option(
        "-t", "--target",
        dest="target",
        help="Specify the target subnet or IP range (e.g., 192.168.31.0/24).",
    )
    (options, _) = parser.parse_args()
    
    if not options.target:
        parser.error("[-] Please specify a target IP or subnet, use --help for more info.")
    
    return options
