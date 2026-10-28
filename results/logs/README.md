# Results

Raw outputs from running the pipeline on the full Friday capture with seed 37. All files are in `logs/`,
listed here in the order the scripts ran.

## Files

| File | Written by | What it contains |
|---|---|---|
| `sha256_friday_pcap.txt` | `sha256sum` | SHA-256 of the downloaded capture; it matches the mirror's record |
| `check_duplicates_first300k.log` | `check_duplicates.py` | 6.5% of the first 300,000 packets are exact repeats, typically 4 µs apart, and only between hosts inside the LAN |
| `extract_friday.log` | `extract_first.py` | 9,997,874 packets read; 536,656 flows; 3,282,716 packets kept; 413,907 capture duplicates removed |
| `label_flows.log` | `labels_flows.py` | flows per label with their first and last start time, and attacker ↔ victim flows per hour |
| `check_labels.log` | `check_labels.py` | flows and minutes per attack compared with CIC's labels, and the minutes only one side marks |
| `check_cic_labels_by_pair.log` | `check_cic_label_by_pairs.py` | how CIC labels the bot pair and the attacker ↔ victim pair in each Friday CSV |
| `make_sample_pcap.log` | `make_sample_pcap.py` | confirms that 55 packets from 12 flows were written |
| `sample_flows.pcap` | `make_sample_pcap.py` | the first 8 packets of 3 random flows per label, copied byte for byte; opens in Wireshark |
| `sample_flows.txt` | `make_sample_pcap.py` | the same packets as text: time since the flow started, direction, IP length and TCP flags |
| `train_eval.log` | `train_eval.py` | precision, recall and false-positive rate of the tree and the forest in all five experiments |
| `metrics.json` | `train_eval.py` | every number from those experiments (see below) |
| `tree_main_N4.txt` | `train_eval.py` | the main decision tree (N = 4, depth 6, 33 leaves) as if/else rules (see below) |
| `inspect_results.log` | `inspect_results.py` | the five diagnostics: payload sizes, oversized packets, missed Bot flows, the N = 3 dip, and precision at lower attack shares |

## Reading `metrics.json`

- The top level holds the settings, `seed` (37), `main_n` (4), `tree_depth` (6) and `features_main` (the 19
  features of the main model), followed by one entry per experiment: `main_temporal`, `main_random`,
  `leave_one_out` (one entry per held-out attack), `ablation` (`behaviour_only` and
  `main_plus_fingerprint`) and `sweep` (one entry per N).
- Each run lists its train and test sizes and label counts, then `tree` and `forest`. Each of those has
  `precision`, `recall`, `false_positive_rate`, `f1`, the confusion counts `tp`, `fp`, `fn` and `tn`, and
  `recall_by_attack`.
- `main_temporal` also has `tree_leaves` and `tree_importance`, which shows how much each feature
  contributes to the tree's decisions.

## Reading `tree_main_N4.txt`

Each line is one test on a feature, for example `pay_fwd_sum <= 21.00` (payload bytes sent by the
initiator in the first 4 packets). At each leaf, `weights: [benign, attack]` gives the number of training
flows of each kind that end there, and `class: True` means the tree calls those flows an attack.

## Paths in the logs

These files come from the first run of the project, when the scripts were in a `src/` folder under
slightly different names (`extract_firstn.py`, `label_flows.py`, `check_cic_labels_by_pair.py`), the data
was in `data/interim/`, and outputs such as `metrics.json` and `sample_flows.pcap` were written directly
into `results/`. So the paths printed in the logs differ from this repository. `check_labels.log` also
mentions a figure and a CSV that are not included here; rerunning `check_labels.py` recreates them. The
scripts in this repository are simplified rewrites, checked to produce the same data files and the same
numbers; a few printed messages are worded differently.

