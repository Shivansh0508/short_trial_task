import argparse
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

#AI
ef first_n_features(flows, packets, n):
    p = packets[packets["idx"] < n]
    p["fwd"] = p["dir"] == 0
    p["bwd"] = p["dir"] == 1
    p["len_fwd"] = p["ip_len"] * p["fwd"]
    p["len_bwd"] = p["ip_len"] * p["bwd"]
    p["pay_fwd"] = p["payload_len"] * p["fwd"]
    p["pay_bwd"] = p["payload_len"] * p["bwd"]
    for name, bit in [("fin", 0x01), ("syn", 0x02), ("rst", 0x04), ("psh", 0x08), ("ack", 0x10)]:
        p[name] = (p["tcp_flags"] & bit) > 0
    p["t_us"] = (p["ts"] * 1e6).round().astype("int64")
    p["gap_us"] = p.groupby("flow_id")["t_us"].diff()

    g = p.groupby("flow_id")
    f = pd.DataFrame(index=flows["flow_id"])
    f["n_pkts"] = g.size()
    f["n_fwd"] = g["fwd"].sum()
    f["n_bwd"] = f["n_pkts"] - f["n_fwd"]
    f["len_fwd_sum"] = g["len_fwd"].sum()
    f["len_bwd_sum"] = g["len_bwd"].sum()
    f["len_min"] = g["ip_len"].min()
    f["len_max"] = g["ip_len"].max()
    f["pay_fwd_sum"] = g["pay_fwd"].sum()
    f["pay_bwd_sum"] = g["pay_bwd"].sum()
    for name in ["fin", "syn", "rst", "psh", "ack"]:
        f[name] = g[name].sum()
    f["dur_us"] = g["t_us"].max() - g["t_us"].min()
    f["iat_min_us"] = g["gap_us"].min()
    f["iat_max_us"] = g["gap_us"].max()
    first = p[p["idx"] == 0].set_index("flow_id")
    f["ttl_fwd_first"] = first["ttl"]
    f["win_fwd_first"] = first["tcp_win"]
    f["win_bwd_first"] = p[p["bwd"]].groupby("flow_id")["tcp_win"].first()
    f = f.fillna(0).astype("int64")
    f["proto"] = flows["proto"].values
    f["dst_port"] = flows["dst_port"].values
    return f.reset_index(drop=True)
