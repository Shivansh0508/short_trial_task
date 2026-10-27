#@AI
import argparse
import zipfile
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument("labelled")
parser.add_argument("--cic-zip", required=True)
parser.add_argument("--fig", required=True)
parser.add_argument("--csv", required=True)
args = parser.parse_args()
attacks = ["Bot", "PortScan", "DDoS"]
schedule = {"Bot": ("10:02", "11:02"), "PortScan": ("13:55", "15:29"), "DDoS": ("15:56", "16:16")}

def cic_minute(timestamp):
    clock = timestamp.split(" ")[1]
    hour, minute = clock.split(":")[:2]
    hour = int(hour)
    if hour < 8:
        hour += 12
    return pd.Timestamp(2017, 7, 7, hour, int(minute))

flows = pd.read_parquet(args.labelled, columns=["start_ts", "label"])
flows = flows[flows["label"].isin(attacks)]
flows["minute"] = (pd.to_datetime(flows["start_ts"], unit="s") - pd.Timedelta(hours=3)).dt.floor("min")
mine = flows.groupby(["label", "minute"]).size()

cic_rows = []
with zipfile.ZipFile(args.cic_zip) as z:
    for name in z.namelist():
        if "Friday" in name and name.endswith(".csv"):
            df = pd.read_csv(z.open(name), usecols=[" Timestamp", " Label"])
            for timestamp, label in zip(df[" Timestamp"], df[" Label"]):
                if label in attacks:
                    cic_rows.append((label, cic_minute(timestamp)))
cic = pd.DataFrame(cic_rows, columns=["label", "minute"]).groupby(["label", "minute"]).size()
both = pd.DataFrame({"mine": mine, "cic": cic}).fillna(0).astype(int).sort_index()
Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
both.to_csv(args.csv)

print("label       my flows  CIC flows  my minutes  CIC minutes   both")
for attack in attacks:
    rows = both.loc[attack]
    in_mine = rows["mine"] > 0
    in_cic = rows["cic"] > 0
    print(f"{attack:<9} {rows['mine'].sum():>10,} {rows['cic'].sum():>10,} "
          f"{in_mine.sum():>11} {in_cic.sum():>12} {(in_mine & in_cic).sum():>6}")
    only_cic = rows[in_cic & ~in_mine]
    only_mine = rows[in_mine & ~in_cic]
    if len(only_cic) > 0:
        text = ", ".join(f"{t:%H:%M}({n})" for t, n in only_cic["cic"].items())
        print(f"    minutes only CIC labels as {attack}: {text}")
    if len(only_mine) > 0:
        text = ", ".join(f"{t:%H:%M}({n})" for t, n in only_mine["mine"].items())
        print(f"    minutes only I label as {attack}: {text}")

fig, axes = plt.subplots(1, 3, figsize=(12, 3.5), sharey=True)
for ax, attack in zip(axes, attacks):
    rows = both.loc[attack]
    start, end = schedule[attack]
    ax.axvspan(pd.Timestamp(f"2017-07-07 {start}"), pd.Timestamp(f"2017-07-07 {end}"),
               color="lightgrey", label="published schedule")
    cic_part = rows[rows["cic"] > 0]
    mine_part = rows[rows["mine"] > 0]
    ax.plot(cic_part.index, cic_part["cic"], "o", markersize=4, color="tab:orange", label="CIC labels")
    ax.plot(mine_part.index, mine_part["mine"], "o", markersize=2, color="tab:blue", label="my labels")
    ax.set_yscale("log")
    ax.set_title(attack)
    ax.set_xlabel("local time (ADT)")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
axes[0].set_ylabel("attack flows per minute")
axes[0].legend()
fig.autofmt_xdate()
fig.tight_layout()
Path(args.fig).parent.mkdir(parents=True, exist_ok=True)
fig.savefig(args.fig, dpi=150)
print(f"wrote {args.fig} and {args.csv}")

