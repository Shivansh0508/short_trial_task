# Short trial task, Track B: detecting attacks from the first packets of a flow
>  @Notes from AI

SOP trial task, Track B (network security and intrusion/DDoS detection). The goal is to separate attack
traffic from benign traffic in the CIC-IDS2017 dataset using only features that a network switch could
compute from the **first few packets of a flow**, report precision and recall, and explain where the
detector fails.

**Random seed:** 37, the last two digits of ID f20230637, used wherever randomness appears.

## Results at a glance

Main setting: a decision tree of depth 6, using features from the first 4 packets of each flow, trained on
the earliest 70% of each class and tested on the latest 30%.

| Model | Precision | Recall | False-positive rate | Recall Bot | Recall PortScan | Recall DDoS |
|---|---|---|---|---|---|---|
| Decision tree (the detector) | 0.9985 | 0.9969 | 0.138% | 0.881 | 0.999 | 1.000 |
| Random forest (reference only) | 1.0000 | 0.9971 | 0.004% | 0.881 | 0.999 | 1.000 |

- **Four packets are enough.** With one packet the false-positive rate is 6.2%; from four packets on, the
  results stay about the same.
- **One feature does most of the work:** payload bytes sent by the initiator. 98.6% of DDoS flows send
  exactly 20 bytes (the attack tool's request), while 99.9% of port scans and 84.7% of bot connections
  send none.
- **Where the detector fails:**
  - An attack type it was never trained on. With DDoS left out of training, DDoS recall is 0.000.
  - A known attack behaving slightly differently. 159 of the 171 missed Bot flows are three-packet flows in
    which every packet carries SYN, which looks like a retried connection attempt, instead of the usual
    SYN followed by RST.
- **Precision depends on how rare attacks are.** About half of the test set is attacks. At the same recall
  and false-positive rate, precision would be 0.879 if 1% of flows were attacks, and 0.419 at 0.1%.

All experiments and numbers are in [Classification/README.md](Classification/README.md).

## Data

- **Dataset:** CIC-IDS2017, the capture of Friday 7 July 2017: benign traffic plus three attacks, Bot
  (ARES), PortScan (nmap) and DDoS (LOIC).
- **Source:** the official download (https://www.unb.ca/cic/datasets/ids-2017.html) needs registration, so
  the files came from the Hugging Face mirror `bencorn/CICIDS2017`, pinned to commit `811c007f`. The
  capture's SHA-256 matches the mirror's record.
- **Not in this repository:** the raw 8.8 GB capture and CIC's 284 MB labelled CSVs, which exceed GitHub's
  file limit. The download commands are below.
- **In this repository:** the processed dataset in [datasets/](datasets/): 536,656 flows and the first 16
  packets of each.
- **Labels** come from the published attack schedule, not from CIC's own CSVs, which turned out to be
  inconsistent (see [notes.md](notes.md)).

| Label | Flows |
|---|---|
| BENIGN | 274,962 |
| PortScan | 161,201 |
| DDoS | 95,683 |
| Bot | 4,803 |
| UNCLEAR (excluded from training and testing) | 7 |

Citation: I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection
Dataset and Intrusion Traffic Characterization", ICISSP 2018.
## Repository layout

```
├── README.md                     this file
├── notes.md                      how the three attacks differ in their first packets; why CIC's labels were not used as-is
├── Dataset Extraction/           raw capture → labelled flow dataset (see its README)
│   ├── README.md
│   ├── check_duplicates.py
│   ├── extract_first.py
│   ├── labels_flows.py
│   ├── check_labels.py
│   ├── check_cic_label_by_pairs.py
│   └── make_sample_pcap.py
├── Classification/               features, training, evaluation and diagnostics (see its README)
│   ├── README.md
│   ├── train_eval.py
│   └── inspect_results.py
├── datasets/                     the processed dataset (see its README)
│   ├── README.md
│   ├── friday_labelled.parquet   one row per flow, with its label (536,656 flows)
│   └── friday_packets.parquet    the first 16 packets of each flow (3,282,716 packets)
└── results/
    └── logs/                     raw outputs of every run, in pipeline order
        ├── sha256_friday_pcap.txt           SHA-256 of the downloaded capture
        ├── check_duplicates_first300k.log   check_duplicates.py, first 300,000 packets
        ├── extract_friday.log               extract_first.py
        ├── label_flows.log                  labels_flows.py
        ├── check_labels.log                 check_labels.py
        ├── check_cic_labels_by_pair.log     check_cic_label_by_pairs.py
        ├── make_sample_pcap.log             make_sample_pcap.py
        ├── sample_flows.pcap                12 example flows (3 per label) for Wireshark, from make_sample_pcap.py
        ├── sample_flows.txt                 the same packets as text
        ├── train_eval.log                   train_eval.py
        ├── metrics.json                     every score from train_eval.py
        ├── tree_main_N4.txt                 the main decision tree as if/else rules, from train_eval.py
        └── inspect_results.log              inspect_results.py
```


## Pipeline

| Step | Script | What it does |
|---|---|---|
| 1 | `Dataset Extraction/check_duplicates.py` | Finds that traffic between LAN hosts was recorded twice |
| 2 | `Dataset Extraction/extract_first.py` | Capture → 536,656 flows with their first 16 packets; duplicates removed |
| 3 | `Dataset Extraction/labels_flows.py` | Labels every flow from the attack schedule |
| 4 | `Dataset Extraction/check_labels.py` | Compares the labels with CIC's, minute by minute |
| 5 | `Dataset Extraction/check_cic_label_by_pairs.py` | Shows where CIC's own labels contradict each other |
| 6 | `Dataset Extraction/make_sample_pcap.py` | Copies 12 example flows into a small capture |
| 7 | `Classification/train_eval.py` | Builds first-N-packet features, trains the models, scores five experiments |
| 8 | `Classification/inspect_results.py` | Explains the numbers, including the failure cases |

## How to reproduce

Python 3.11. Commands are for Git Bash (or any Linux/macOS shell), run from the repository root.

```bash
pip install dpkt==1.9.8 numpy==2.4.6 pandas==3.1.0 pyarrow==26.0.0 scikit-learn==1.9.1 matplotlib==3.11.2
```

**Classification only (no download needed).** The two files in `datasets/` are enough:

```bash
python Classification/train_eval.py datasets/friday_labelled.parquet datasets/friday_packets.parquet --out results --seed 37
python Classification/inspect_results.py datasets/friday_labelled.parquet datasets/friday_packets.parquet
```

The first command takes about a minute. It writes `results/metrics.json` (every score) and
`results/tree_main_N4.txt` (the main tree as if/else rules), creating the `results/` folder if needed.
The second prints the diagnostics and reads `results/metrics.json`. For a quick variation, add
`--sweep 4` and change one setting such as `--depth 4` or `--main-n 8`, with `--out` pointing to a new
folder.

**Full pipeline from the raw capture:**

```bash
mkdir -p data/raw/labels
curl -L --fail -o data/raw/Friday-WorkingHours.pcap \
  "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/pcaps/Friday-WorkingHours.pcap"
curl -L --fail -o data/raw/labels/GeneratedLabelledFlows.zip \
  "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/csvs/GeneratedLabelledFlows.zip"
sha256sum data/raw/Friday-WorkingHours.pcap
# expected: beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0

python "Dataset Extraction/check_duplicates.py" data/raw/Friday-WorkingHours.pcap 300000
python "Dataset Extraction/extract_first.py" data/raw/Friday-WorkingHours.pcap --out datasets/friday --k 16
python "Dataset Extraction/labels_flows.py" datasets/friday_flows.parquet --out datasets/friday_labelled.parquet
python "Dataset Extraction/check_labels.py" datasets/friday_labelled.parquet \
    --cic-zip data/raw/labels/GeneratedLabelledFlows.zip \
    --fig results/figures/label_check.png --csv results/label_check_per_minute.csv
python "Dataset Extraction/check_cic_label_by_pairs.py" data/raw/labels/GeneratedLabelledFlows.zip
python "Dataset Extraction/make_sample_pcap.py" data/raw/Friday-WorkingHours.pcap datasets/friday_labelled.parquet \
    --out results/sample_flows.pcap
```

Then run the two classification commands above. `extract_first.py` and `make_sample_pcap.py` read the
whole capture and take a few minutes each. These steps rebuild the two files in `datasets/` with the same
contents, add `datasets/friday_flows.parquet`, and save the label cross-check and the sample capture in
`results/`.

## Limitations

- **One day, one network.** All traffic comes from a single capture, with one tool per attack. The
  detector has not been tested on other days or other attack tools, and it can miss attack types it was
  not trained on.
- **High attack share in the test set.** About half of the test flows are attacks, far more than on a real
  network, which makes precision look better than it would be in practice.
- **Capture artefacts.** The capture machine merged TCP segments into packets larger than a switch would
  see. Within the first 4 packets this affects at most 0.5% of flows, but much more at larger N.
- **Not run on a switch.** The features and the tree are designed to fit a programmable switch, but the
  detector was only evaluated offline in Python.
- **Labels come from the schedule.** Flows between the attacker and the victim are labelled by time window,
  so any benign traffic between those two hosts during an attack is labelled as attack.

## Use of AI tools

An AI coding assistant (Claude Code, by Anthropic) was used to write the scripts in `Dataset Extraction/`
and `Classification/`, run the experiments, draft this README and the two folder READMEs, and help write
`notes.md`. The scripts were later rewritten in a simpler style, and each rewrite was checked to give the
same results.
