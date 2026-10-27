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
            seq, flags = l4.seq, l4.flags
        elif isinstance(l4, dpkt.udp.UDP):
            seq, flags = 0, 0
        else:
            continue

        a = dpkt.utils.inet_to_str(ip.src)
        b = dpkt.utils.inet_to_str(ip.dst)
        pair = (min(a, b), max(a, b))
        pair_count[pair] += 1
        key = (ip.src, ip.dst, ip.id, ip.p, l4.sport, l4.dport, seq, ip.len, flags)
        if key in seen:
            first_ts, first_ttl = seen[key]
            dups += 1
            pair_dups[pair] += 1
            gaps.append(ts - first_ts)
            if first_ttl == ip.ttl:
                same_ttl += 1
        else:
            seen[key] = (ts, ip.ttl)
