from scapy.all import *
import os
import shlex
import subprocess as sp
import sys
import re
import json
from scapy.packet import Raw

ARP_CACHE_CMD = 'arp -na'
ARP_CACHE_RXP = '.*\((\S+)\)\s+at\s+(\S+)\s+.*on\s+(.*)'

SCAN_INTERVAL = 3

ALERT_SERVER = '10.0.0.100'
ALERT_PORT = 10000
ALERT_COUNT = 3



def get_arp_table():

    arp_table = dict()
    cache_rxp = re.compile(ARP_CACHE_RXP)

    cache_lines = sp.Popen( shlex.split(ARP_CACHE_CMD), stdout=sp.PIPE, stderr=sp.PIPE )
    for entry in cache_lines.communicate()[0].split('\n'):

        if cache_rxp.match(entry) is None: continue

        ( d_ip, d_mac, iface ) = cache_rxp.match(entry).groups()

        try: arp_table[d_ip]
        except: arp_table[d_ip] = dict()

        arp_table[d_ip]['mac'] = d_mac
        arp_table[d_ip]['iface'] = iface

    return arp_table



def send_alarm( notification, d_mac, d_ip, d_port, count, d_iface ):

    # -- Craft UDP alert message
    eth_=Ether()
    eth_.dst="%s" %d_mac

    ip_=IP()
    ip_.dst="%s" %d_ip

    udp_ = UDP()
    udp_.dport=int(d_port)

    udp_.payload="%s" %notification

    pkt=eth_/ip_/udp_

    # -- push message out of corresponding intface
    while count > 0:

        print 'Message:%s\n\tVia-mac %s\n\tTo-Dest %s:%s' %( notification, d_mac, d_ip, d_port )
        sendp(str(pkt), iface="%s"%d_iface)

        count -= 1

        if count == 0: print; print; print



if __name__=='__main__':

    arp_database = get_arp_table()

    while True:

        time.sleep(SCAN_INTERVAL)

        arp_table = get_arp_table()

        # -- iterate over latest batch of arp_entries
        for ip_address in arp_table.keys():

            # -- update arp_database with new entries
            if ip_address not in arp_database: 
                arp_database[ip_address] = arp_table[ip_address]

            # -- skip if new mac matches old mac
            if arp_table[ip_address]['mac'] == arp_database[ip_address]['mac']: 
                continue

            # -- we found a conflict, take action
            notification = 'ALERT: IP<%s> changed MAC from <%s> to <%s>' %(
                ip_address, arp_database[ip_address]['mac'], arp_table[ip_address]['mac'])

            # -- forward notification to old-mac
            send_alarm( notification, arp_database[ip_address]['mac'], 
                ALERT_SERVER, ALERT_PORT, ALERT_COUNT, arp_database[ip_address]['iface'] )

            # -- update MAC in database
            arp_database[ip_address]['mac'] = arp_table[ip_address]['mac']
            arp_database[ip_address]['iface'] = arp_table[ip_address]['iface']



        


    
