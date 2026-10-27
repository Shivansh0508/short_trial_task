import argparse
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument("flows")
parser.add_argument("--out", required=True)
args = parser.parse_args()
attacker = "172.16.0.1"
victim = "192.168.10.50"
bot_server = "205.174.165.73"
bot_victims = ["192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"]

def get_label(src, dst, start):
    if src == bot_server and dst in bot_victims:
        return "Bot"
    if dst == bot_server and src in bot_victims:
        return "Bot"
    if (src == attacker and dst == victim) or (src == victim and dst == attacker):
        if "13:00" <= start < "15:40":
            return "PortScan"
        if "15:40" <= start < "16:30":
            return "DDoS"
        return "UNCLEAR"
    return "BENIGN"

flows = pd.read_parquet(args.flows)
local_time = pd.to_datetime(flows["start_ts"], unit="s") - pd.Timedelta(hours=3)
start_hhmm = local_time.dt.strftime("%H:%M")

labels = []
for src, dst, start in zip(flows["src_ip"], flows["dst_ip"], start_hhmm):
    labels.append(get_label(src, dst, start))
flows["label"] = labels
flows.to_parquet(args.out, index=False)

# @AI
print(f"{len(flows):,} flows, local time {local_time.min():%H:%M:%S} -> {local_time.max():%H:%M:%S}")
for label, group in flows.groupby("label"):
    times = local_time[group.index]
    print(f"{label:10} {len(group):>8,} flows   first {times.min():%H:%M:%S}   last {times.max():%H:%M:%S}   "
          f"median packets {group['n_pkts_total'].median()}")

attack = flows[flows["label"].isin(["PortScan", "DDoS", "UNCLEAR"])]
print("\n172.16.0.1 <-> 192.168.10.50 flows by local hour:")
print(pd.crosstab(local_time[attack.index].dt.hour.rename("hour"), attack["label"]))
print(f"\nwrote {args.out}")
