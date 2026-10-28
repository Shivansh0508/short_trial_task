import argparse
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

ATTACKS = ["Bot", "PortScan", "DDoS"]
BEHAVIOUR = ["n_pkts", "n_fwd", "n_bwd", "len_fwd_sum", "len_bwd_sum", "len_min", "len_max", "pay_fwd_sum", "pay_bwd_sum", "syn", "ack", "fin", "rst", "psh", "dur_us", "iat_min_us", "iat_max_us"]
PORT = ["proto", "dst_port"]
FINGERPRINT = ["ttl_fwd_first", "win_fwd_first", "win_bwd_first"]
MAIN_FEATURES = BEHAVIOUR + PORT

#AI
def first_n_features(flows, packets, n):
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

def temporal_split(flows):
    train = np.zeros(len(flows), dtype=bool)
    for label, group in flows.groupby("label"):
        group = group.sort_values("start_ts", kind="stable")
        n_train = round(0.7 * len(group))
        train[group.index[:n_train]] = True
    return train

def random_split(flows, seed):
    train_rows, test_rows = train_test_split(flows.index, train_size=0.7, stratify=flows["label"], random_state=seed)
    train = np.zeros(len(flows), dtype=bool)
    train[train_rows] = True
    return train

def scores(labels, pred):
    actual = (labels != "BENIGN").to_numpy()
    tp = int((actual & pred).sum())
    fp = int((~actual & pred).sum())
    fn = int((actual & ~pred).sum())
    tn = int((~actual & ~pred).sum())
    result = {
        "precision": tp / max(tp + fp, 1),
        "recall": tp / max(tp + fn, 1),
        "false_positive_rate": fp / max(fp + tn, 1),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }
    result["f1"] = 2 * result["precision"] * result["recall"] / max(result["precision"] + result["recall"], 1e-12)
    by_attack = {}
    for attack in ATTACKS:
        rows = (labels == attack).to_numpy()
        if rows.any():
            by_attack[attack] = float(pred[rows].mean())
    result["recall_by_attack"] = by_attack
    return result

def run(X, labels, train, test, features, seed, depth):
    result = {
        "n_train": int(train.sum()),
        "n_test": int(test.sum()),
        "train_counts": labels[train].value_counts().to_dict(),
        "test_counts": labels[test].value_counts().to_dict(),
    }
    y_train = (labels[train] != "BENIGN").to_numpy()
    tree = DecisionTreeClassifier(max_depth=depth, random_state=seed)
    forest = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed)
    for name, model in [("tree", tree), ("forest", forest)]:
        model.fit(X.loc[train, features], y_train)
        pred = model.predict(X.loc[test, features]).astype(bool)
        result[name] = scores(labels[test], pred)
    return result, tree


def summary_line(result):
    tree = result["tree"]
    forest = result["forest"]
    by_attack = " ".join(f"{a}={v:.3f}" for a, v in tree["recall_by_attack"].items())
    return (f"tree P={tree['precision']:.4f} R={tree['recall']:.4f} FPR={tree['false_positive_rate']:.5f} [{by_attack}] | "f"forest P={forest['precision']:.4f} R={forest['recall']:.4f} FPR={forest['false_positive_rate']:.5f}")


#@AI
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("labelled")
    parser.add_argument("packets")
    parser.add_argument("--out", default="results")
    parser.add_argument("--seed", type=int, default=37)
    parser.add_argument("--main-n", type=int, default=4)
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument("--sweep", default="1,2,3,4,6,8,12,16")
    args = parser.parse_args()
    start = time.time()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    flows = pd.read_parquet(args.labelled)
    flows = flows[flows["label"] != "UNCLEAR"].reset_index(drop=True)
    packets = pd.read_parquet(args.packets)
    packets = packets[packets["flow_id"].isin(flows["flow_id"])].sort_values(["flow_id", "idx"], kind="stable")
    labels = flows["label"]
    print(f"{len(flows):,} flows (UNCLEAR dropped): {labels.value_counts().to_dict()}")

    temporal_train = temporal_split(flows)
    random_train = random_split(flows, args.seed)
    X = first_n_features(flows, packets, args.main_n)
    results = {"seed": args.seed, "main_n": args.main_n, "tree_depth": args.depth, "features_main": MAIN_FEATURES}

    print(f"\n[1] main: N={args.main_n}, temporal split")
    result, tree = run(X, labels, temporal_train, ~temporal_train, MAIN_FEATURES, args.seed, args.depth)
    print("   ", summary_line(result))
    importance = pd.Series(tree.feature_importances_, index=MAIN_FEATURES).sort_values(ascending=False)
    importance = importance[importance > 0]
    result["tree_leaves"] = int(tree.get_n_leaves())
    result["tree_importance"] = importance.round(4).to_dict()
    results["main_temporal"] = result
    print(f"    tree: {tree.get_n_leaves()} leaves; importance: "
          + ", ".join(f"{name}={value:.3f}" for name, value in importance.items()))
    tree_text = export_text(tree, feature_names=MAIN_FEATURES, show_weights=True)
    (out / f"tree_main_N{args.main_n}.txt").write_text(tree_text)

    print(f"\n[2] random stratified split, N={args.main_n}")
    result, tree = run(X, labels, random_train, ~random_train, MAIN_FEATURES, args.seed, args.depth)
    results["main_random"] = result
    print("   ", summary_line(result))

    print(f"\n[3] leave one attack out, N={args.main_n} (train: benign + other attacks; test: benign + held-out attack)")
    results["leave_one_out"] = {}
    benign = (labels == "BENIGN").to_numpy()
    for held in ATTACKS:
        is_held = (labels == held).to_numpy()
        train = temporal_train & ~is_held
        test = (~temporal_train & benign) | is_held
        result, tree = run(X, labels, train, test, MAIN_FEATURES, args.seed, args.depth)
        results["leave_one_out"][held] = result
        print(f"    held out {held:<8}", summary_line(result))

    print(f"\n[4] feature ablation, N={args.main_n}, temporal split")
    results["ablation"] = {}
    for name, features in [("behaviour_only", BEHAVIOUR), ("main_plus_fingerprint", MAIN_FEATURES + FINGERPRINT)]:
        result, tree = run(X, labels, temporal_train, ~temporal_train, features, args.seed, args.depth)
        results["ablation"][name] = result
        print(f"    {name:<22}", summary_line(result))

    print("\n[5] sweep over N, temporal split")
    results["sweep"] = {}
    for n in args.sweep.split(","):
        n = int(n)
        if n == args.main_n:
            Xn = X
        else:
            Xn = first_n_features(flows, packets, n)
        result, tree = run(Xn, labels, temporal_train, ~temporal_train, MAIN_FEATURES, args.seed, args.depth)
        results["sweep"][n] = result
        print(f"    N={n:<3}", summary_line(result))

    (out / "metrics.json").write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out / 'metrics.json'}  ({time.time() - start:.0f}s)")


if __name__ == "__main__":
    main()

