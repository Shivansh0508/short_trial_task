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

print(f"packets examined: {packets:,}   exact repeats (same IP id/seq/len/flags): {dups:,} ({100 * dups / packets:.1f}%)")
if dups == 0:
    sys.exit()

gaps = np.array(gaps)
print("time between copies (s): median %.6f  p95 %.6f  max %.3f" % (np.median(gaps), np.percentile(gaps, 95), gaps.max()))
print(f"copies with identical TTL: {100 * same_ttl / dups:.1f}%")

print("duplicate share by host pair (top 10 by volume):")
for pair, total in pair_count.most_common(10):
    print(f"  {pair[0]:>16} <-> {pair[1]:<16} pkts {total:>8,}  dup {100 * pair_dups[pair] / total:5.1f}%")

print("\nhost pairs with the most duplicates:")
for pair, d in pair_dups.most_common(12):
    total = pair_count[pair]
    print(f"  {pair[0]:>16} <-> {pair[1]:<16} dup {d:>7,} of {total:>8,}  ({100 * d / total:5.1f}%)")

for seconds in (0.0001, 0.001, 0.01, 1.0):
    print(f"repeats closer than {seconds * 1000:g} ms: {100 * (gaps < seconds).mean():.2f}%")
