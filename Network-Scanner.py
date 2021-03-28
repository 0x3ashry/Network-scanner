import scapy.all as scapy
import argparse

def parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--ip",dest="ip_address",help="The IP Target / IP Range to scan.")
    options = parser.parse_args()
    return options.ip_address


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # instead of storing an entire unanswered_list {answered_list,unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)}

    ip_table = []
    for element in answered_list:
        dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        ip_table.append(dict)
    return ip_table


def display(ip_table):
    print("IP\t\t\tMAC Address\n-----------------------------------------------------------")
    for device in ip_table:
        print(device["ip"] + "\t\t" + device["mac"])


#----------------------------------------------------------MAIN---------------------------------------------------------

ip_address = parsing()
scan_result = scan(ip_address)
display(scan_result)
