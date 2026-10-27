import sys
from collections import Counter
import dpkt
import numpy as np

path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/Friday-WorkingHours.pcap"
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 300000
seen = {}
gaps = []
same_ttl = 0
dups = 0
packets = 0
pair_count = Counter()
pair_dups = Counter()  

with open(path, "rb") as f:
    for ts, buf in dpkt.pcapng.Reader(f):
        if packets == limit:
            break
        packets += 1

        ip = dpkt.ethernet.Ethernet(buf).data
        if not isinstance(ip, dpkt.ip.IP):
            continue

        l4 = ip.data
        if isinstance(l4, dpkt.tcp.TCP):
