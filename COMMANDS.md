# Commands run, in order

Machine: Windows 11, Git Bash, Python 3.11.9. All commands run from the repo root unless noted.

## 1. Setup (2026-10-27)

```bash
git init -b main
"$LOCALAPPDATA/Programs/Python/Python311/python.exe" -m venv .venv
./.venv/Scripts/python.exe -m pip install --upgrade pip
./.venv/Scripts/python.exe -m pip install numpy pandas scikit-learn dpkt matplotlib pyarrow
./.venv/Scripts/python.exe -m pip freeze   # versions pinned in requirements.txt
```

## 2. Data download

```bash
mkdir -p data/raw
curl -L --fail --retry 5 --retry-delay 5 -C - -o data/raw/Friday-WorkingHours.pcap \
  "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/pcaps/Friday-WorkingHours.pcap"
```

## 3. Format and duplicate checks (run on the partial download)

```bash
# dpkt said "invalid tcpdump header"; the magic bytes show the file is pcapng, not pcap
head -c 64 data/raw/Friday-WorkingHours.pcap | od -A d -t x1 | head -5

# Smoke test of the extractor on the first 1M packets
./.venv/Scripts/python.exe -I src/extract_firstn.py data/raw/Friday-WorkingHours.pcap --out data/interim/test1m --max-packets 1000000

# Repeated packets showed up inside flows; measure how often, how far apart, and for which hosts
./.venv/Scripts/python.exe -I src/check_duplicates.py data/raw/Friday-WorkingHours.pcap 300000 | tee results/logs/check_duplicates_first300k.log
```

## 4. Full capture: verify, extract, label, cross-check

```bash
sha256sum data/raw/Friday-WorkingHours.pcap | tee results/logs/sha256_friday_pcap.txt   # matches data/SOURCES.md
./.venv/Scripts/python.exe -I src/extract_firstn.py data/raw/Friday-WorkingHours.pcap --out data/interim/friday --k 16 \
    2>&1 | tee results/logs/extract_friday.log
./.venv/Scripts/python.exe -I src/label_flows.py data/interim/friday_flows.parquet --out data/interim/friday_labelled.parquet \
    2>&1 | tee results/logs/label_flows.log

# CIC's labelled CSVs, used only to cross-check my labels (SHA-256 7bdbef28... matches the mirror)
mkdir -p data/raw/labels
curl -L --fail -o data/raw/labels/GeneratedLabelledFlows.zip \
  "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/csvs/GeneratedLabelledFlows.zip"
./.venv/Scripts/python.exe -I src/check_labels.py data/interim/friday_labelled.parquet \
    --cic-zip data/raw/labels/GeneratedLabelledFlows.zip --fig results/figures/label_check.png \
    --csv results/label_check_per_minute.csv > results/logs/check_labels.log 2>&1
./.venv/Scripts/python.exe -I src/check_cic_labels_by_pair.py data/raw/labels/GeneratedLabelledFlows.zip \
    > results/logs/check_cic_labels_by_pair.log 2>&1
```

## 5. Train, evaluate, diagnose, plot (seed 37)

```bash
./.venv/Scripts/python.exe -I src/train_eval.py data/interim/friday_labelled.parquet data/interim/friday_packets.parquet \
    --out results --seed 37 > results/logs/train_eval.log 2>&1          # ~80 s; writes results/metrics.json, results/tree_main_N4.txt
./.venv/Scripts/python.exe -I src/make_sample_pcap.py data/raw/Friday-WorkingHours.pcap data/interim/friday_labelled.parquet \
    --out results/sample_flows.pcap 2>&1 | tee results/logs/make_sample_pcap.log
./.venv/Scripts/python.exe -I src/inspect_results.py data/interim/friday_labelled.parquet data/interim/friday_packets.parquet \
    > results/logs/inspect_results.log 2>&1
./.venv/Scripts/python.exe -I src/plot_results.py                       # results/figures/{recall_by_setting,n_sweep}.png
```

Note: the false-positive breakdown in section 4 of `inspect_results.log` was first run as an inline
one-off script while investigating why N=3 scored worse than N=2, then moved into `inspect_results.py`.

