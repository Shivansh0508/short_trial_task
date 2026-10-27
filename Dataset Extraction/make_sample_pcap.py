import argparse
from pathlib import Path

import dpkt
import pandas as pd
from dpkt.utils import inet_to_str

parser = argparse.ArgumentParser()
parser.add_argument("pcap")
parser.add_argument("labelled")
parser.add_argument("--out", required=True)
parser.add_argument("--per-class", type=int, default=3)
parser.add_argument("--packets", type=int, default=8)
parser.add_argument("--seed", type=int, default=37)
args = parser.parse_args()


def flag_letters(flags):
    letters = ""
    for bit, letter in [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U")]:
        if flags & bit:
            letters += letter
    return letters or "-"


flows = pd.read_parquet(args.labelled)
flows = flows[flows["label"] != "UNCLEAR"]
chosen = flows.groupby("label").sample(n=args.per_class, random_state=args.seed)

picked = {}
for flow in chosen.itertuples():
    src = (flow.src_ip, flow.src_port)
    dst = (flow.dst_ip, flow.dst_port)
    picked[(min(src, dst), max(src, dst), flow.proto)] = flow
count = {key: 0 for key in picked}
lines = {key: [] for key in picked}

Path(args.out).parent.mkdir(parents=True, exist_ok=True)
with open(args.pcap, "rb") as f, open(args.out, "wb") as out:
    writer = dpkt.pcap.Writer(out)
    for ts, buf in dpkt.pcapng.Reader(f):
        ip = dpkt.ethernet.Ethernet(buf).data
        if not isinstance(ip, dpkt.ip.IP):
            continue
        l4 = ip.data
        if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            continue

        src = (inet_to_str(ip.src), l4.sport)
        dst = (inet_to_str(ip.dst), l4.dport)
        key = (min(src, dst), max(src, dst), ip.p)
        if key not in picked:
            continue
        flow = picked[key]
        if ts < flow.start_ts - 1e-6 or ts > flow.last_ts + 1e-6:
            continue
        if count[key] >= args.packets:
            continue

        count[key] += 1
        writer.writepkt(buf, ts)
        direction = "->" if src == (flow.src_ip, flow.src_port) else "<-"
        flags = l4.flags if ip.p == 6 else 0
        lines[key].append(f"    {ts - flow.start_ts:10.6f}s  {direction}  len={ip.len:<5} flags={flag_letters(flags)}")

txt_path = Path(args.out).with_suffix(".txt")
with open(txt_path, "w") as f:
    f.write(f"First {args.packets} packets (as captured) of {args.per_class} random flows per label, seed {args.seed}\n")
    f.write("time is relative to flow start; -> is initiator to responder\n")
    f.write("capture duplicates are kept here, but 'packets in total' is counted after removing them\n")
    for key, flow in picked.items():
        f.write(f"\n[{flow.label}] flow {flow.flow_id}: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                f"proto {flow.proto}, {flow.n_pkts_total} packets in total\n")
        f.write("\n".join(lines[key]) + "\n")
print(f"wrote {sum(count.values())} packets from {len(picked)} flows to {args.out} and {txt_path}")

