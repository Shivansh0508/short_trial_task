@AI
import argparse
import time
from pathlib import Path
import dpkt
import pandas as pd
from dpkt.tcp import TH_ACK, TH_FIN, TH_RST, TH_SYN
from dpkt.utils import inet_to_str

parser = argparse.ArgumentParser()
parser.add_argument("pcap")
parser.add_argument("--out", required=True)
parser.add_argument("--k", type=int, default=16)
parser.add_argument("--idle-timeout", type=float, default=120.0)
parser.add_argument("--dup-window", type=float, default=0.001)
parser.add_argument("--max-packets", type=int, default=0)
args = parser.parse_args()

flows = []
latest_flow = {}
kept_packets = []
recent = {}
last_cleanup = 0
skipped = {"non_ipv4": 0, "not_tcp_udp": 0, "ip_fragment": 0, "truncated": 0, "capture_duplicate": 0}
count = 0
first_ts = None
last_ts = None
start = time.time()

with open(args.pcap, "rb") as f:
    for ts, buf in dpkt.pcap.UniversalReader(f):
        if args.max_packets and count == args.max_packets:
            break
        count += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        if count % 2_000_000 == 0:
            print(f"  {count:,} packets, {len(flows):,} flows, {time.time() - start:.0f}s", flush=True)

        ip = dpkt.ethernet.Ethernet(buf).data
        if not isinstance(ip, dpkt.ip.IP):
            skipped["non_ipv4"] += 1
            continue
        if ip.p not in (6, 17):
            skipped["not_tcp_udp"] += 1
            continue
        if ip.offset != 0:
            skipped["ip_fragment"] += 1
            continue

        l4 = ip.data
        if isinstance(l4, dpkt.tcp.TCP):
            flags = l4.flags
            win = l4.win
            payload_len = ip.len - ip.hl * 4 - l4.off * 4
        elif isinstance(l4, dpkt.udp.UDP):
            flags = 0
            win = 0
            payload_len = ip.len - ip.hl * 4 - 8
        else:
            skipped["truncated"] += 1
            continue

        if ts - last_cleanup > 1:
            recent = {sig: t for sig, t in recent.items() if ts - t < args.dup_window}
            last_cleanup = ts
        sig = buf[14:14 + ip.hl * 4 + 16]
        if sig in recent and ts - recent[sig] < args.dup_window:
            skipped["capture_duplicate"] += 1
            continue
        recent[sig] = ts

        src = (inet_to_str(ip.src), l4.sport)
        dst = (inet_to_str(ip.dst), l4.dport)
        key = (min(src, dst), max(src, dst), ip.p)

        flow = latest_flow.get(key)
        new_syn = flags & TH_SYN and not flags & TH_ACK
        if flow is None or ts - flow["last_ts"] > args.idle_timeout or (flow["closed"] and new_syn):
            flow = {
                "flow_id": len(flows),
                "src_ip": src[0],
                "src_port": src[1],
                "dst_ip": dst[0],
                "dst_port": dst[1],
                "proto": ip.p,
                "start_ts": ts,
                "last_ts": ts,
                "n_pkts_total": 0,
                "closed": False,
            }
            flows.append(flow)
            latest_flow[key] = flow

        position = flow["n_pkts_total"]
        flow["n_pkts_total"] += 1
        flow["last_ts"] = ts
        if flags & (TH_FIN | TH_RST):
            flow["closed"] = True

        if position < args.k:
            direction = 0 if src == (flow["src_ip"], flow["src_port"]) else 1
            kept_packets.append((flow["flow_id"], position, ts, direction, ip.len, ip.ttl, flags, win, payload_len))

print(f"done: {count:,} packets read in {time.time() - start:.0f}s")
print(f"      {len(flows):,} flows, {len(kept_packets):,} packets kept (first {args.k} per flow)")
print(f"      skipped: {skipped}")
print(f"      capture time range (UTC): {pd.to_datetime(first_ts, unit='s')} -> {pd.to_datetime(last_ts, unit='s')}")

columns = ["flow_id", "idx", "ts", "dir", "ip_len", "ttl", "tcp_flags", "tcp_win", "payload_len"]
packets = pd.DataFrame(kept_packets, columns=columns)
packets = packets.astype({"flow_id": "int32", "idx": "uint8", "dir": "uint8", "ip_len": "uint16", "ttl": "uint8", "tcp_flags": "uint8", "tcp_win": "uint16", "payload_len": "int32"})

flow_table = pd.DataFrame(flows).drop(columns="closed")
flow_table = flow_table.astype({"flow_id": "int32", "src_port": "uint16", "dst_port": "uint16", "proto": "uint8"})

Path(args.out).parent.mkdir(parents=True, exist_ok=True)
flow_table.to_parquet(f"{args.out}_flows.parquet", index=False)
packets.to_parquet(f"{args.out}_packets.parquet", index=False)
print(f"wrote {args.out}_flows.parquet and {args.out}_packets.parquet")

