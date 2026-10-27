#@AI
import argparse
import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, str(Path(__file__).parent))
from train_eval import MAIN_FEATURES, first_n_features, temporal_split
parser = argparse.ArgumentParser()
parser.add_argument("labelled")
parser.add_argument("packets")
parser.add_argument("--metrics", default="results/metrics.json")
parser.add_argument("--seed", type=int, default=37)
parser.add_argument("--depth", type=int, default=6)
args = parser.parse_args()


def fit_tree(X, labels, train):
    tree = DecisionTreeClassifier(max_depth=args.depth, random_state=args.seed)
    tree.fit(X.loc[train, MAIN_FEATURES], (labels[train] != "BENIGN").to_numpy())
    return tree

def top_splits(tree):
    splits = []
    for feature, threshold in zip(tree.tree_.feature[:16], tree.tree_.threshold[:16]):
        if feature >= 0:
            splits.append((MAIN_FEATURES[feature], round(float(threshold), 1)))
    return splits[:4]


flows = pd.read_parquet(args.labelled)
flows = flows[flows["label"] != "UNCLEAR"].reset_index(drop=True)
packets = pd.read_parquet(args.packets)
packets = packets[packets["flow_id"].isin(flows["flow_id"])].sort_values(["flow_id", "idx"], kind="stable")
labels = flows["label"]
train = temporal_split(flows)

X = {}
trees = {}
for n in (2, 3, 4):
    X[n] = first_n_features(flows, packets, n)
    trees[n] = fit_tree(X[n], labels, train)
X[16] = first_n_features(flows, packets, 16)

print("1. forward payload bytes in the first 4 packets: most common values per class (share of flows)")
for label in ["BENIGN", "Bot", "DDoS", "PortScan"]:
    values = X[4].loc[labels == label, "pay_fwd_sum"]
    top = values.value_counts(normalize=True).head(4)
    print(f" {label:<9} " + ", ".join(f"{int(value)} B: {share:.1%}" for value, share in top.items()))

print("\n2. flows with a >1500-byte packet (receive-offload artifact) among their first N packets")
for n in (4, 16):
    has_big_packet = X[n]["len_max"] > 1500
    share = has_big_packet.groupby(labels).mean()
    print(f"  N={n:<3}" + "  ".join(f"{label}: {value:.2%}" for label, value in share.items()))

print("\n3. Bot test flows: caught vs missed by the main tree (N=4)")
bot_test = ~train & (labels == "Bot").to_numpy()
caught = trees[4].predict(X[4].loc[bot_test, MAIN_FEATURES]).astype(bool)
shapes = pd.Series([f"pkts={r.n_pkts} syn={r.syn} rst={r.rst} pay_fwd={r.pay_fwd_sum} port={r.dst_port}"
                    for r in X[4][bot_test].itertuples()])
for name, mask in [("caught", caught), ("missed", ~caught)]:
    print(f"   {name}: {mask.sum():,} flows; most common shapes:")
    for shape, count in shapes[mask].value_counts().head(3).items():
        print(f" {count:>5,}  {shape}")

print("\n4. N=2 vs N=3 vs N=4: DDoS recall over the DDoS test period (in 5 equal time slices), and top tree splits")
ddos_test = np.flatnonzero(~train & (labels == "DDoS").to_numpy())
ddos_test = ddos_test[np.argsort(flows["start_ts"].values[ddos_test])]
for n in (2, 3, 4):
    caught = trees[n].predict(X[n].loc[ddos_test, MAIN_FEATURES]).astype(bool)
    slices = " ".join(f"{part.mean():.3f}" for part in np.array_split(caught, 5))
    print(f"  N={n}: DDoS recall by time slice [{slices}]  top splits: {top_splits(trees[n])}")

ddos = (labels == "DDoS").to_numpy()
for n in (2, 3):
    durations = X[n][ddos]
    durations["train"] = train[ddos]
    q = durations.groupby("train")["dur_us"].quantile([0.1, 0.5, 0.9]).unstack().round(0)
    q.index = q.index.map({True: "train", False: "test"})
    print(f" DDoS dur_us quantiles at N={n} (train vs test):\n" + q.to_string().replace("\n", "\n  "))

benign_test = ~train & (labels == "BENIGN").to_numpy()
for n in (2, 3):
    flagged = trees[n].predict(X[n].loc[benign_test, MAIN_FEATURES]).astype(bool)
    wrong_flows = flows[benign_test][flagged]
    wrong_features = X[n][benign_test][flagged]
    shapes = pd.Series([f"pkts={r.n_pkts} fwd={r.n_fwd} syn={r.syn} ack={r.ack} rst={r.rst} len_min={r.len_min}"
                        for r in wrong_features.itertuples()])
    ports = wrong_flows["dst_port"].value_counts().head(4).to_dict()
    print(f" N={n}: {flagged.sum():,} benign false positives; top dst ports {ports}")
    print(f" top shapes {shapes.value_counts().head(2).to_dict()}")

print("\n5. precision of the main tree if attacks were rarer (same recall and false-positive rate)")
with open(args.metrics) as f:
    main_tree = json.load(f)["main_temporal"]["tree"]
recall = main_tree["recall"]
fpr = main_tree["false_positive_rate"]
for share in (0.5, 0.1, 0.01, 0.001):
    precision = recall * share / (recall * share + fpr * (1 - share))
    print(f" attack share {share:>6.1%}: precision {precision:.3f}")
