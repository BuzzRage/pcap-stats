#!/usr/bin/env python3
from scapy.all import *
from matplotlib import pyplot as mp
import numpy as np


PCAP_MODE = True

if PCAP_MODE:
    # Read data from a .pcap file
    data_path = "./pcap/test-iperf3-29062021-1525.pcap"
    print("Loading file "+data_path+"...")
    capture = rdpcap(data_path)
    print("File "+data_path+" is loaded !")
else:
    # Or capture live packets !
    print("Sniffing the network with the following filter: "+filter_str+"...")
    filter_str = "host 10.35.1.58"
    capture = sniff(filter=filter_str, timeout = 10, count = 50)

tsval = 0
tsecr = 0

rtt_list = list()

print(str(len(capture)) + " packtes captured.")

for pkt in capture:
    #if pkt['IP'].src == "172.16.20.24":
        
    tsdata = dict(pkt['TCP'].options)
    tsvalpkt = tsdata['Timestamp'][0]
    tsecrpkt = tsdata['Timestamp'][1]

    if tsval == tsecrpkt:
        rtt = tsvalpkt - tsecr
        if rtt != 0 and tsecr != 0:
            rtt_list.append(rtt)
    
    tsval = tsvalpkt
    tsecr = tsecrpkt

print(str(len(rtt_list)) + " RTT values calculated.")

plt.hist(rtt_list)
plt.xlabel("RTT in ms")
plt.ylabel("Occurrence")
plt.show()

