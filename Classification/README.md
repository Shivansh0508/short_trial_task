
# Classification

These two scripts train and test the attack detector on the dataset built in `Dataset Extraction`, then
explain the results. `train_eval.py` runs first: `inspect_results.py` reuses its feature code and reads the
`results/metrics.json` it writes, so both files must stay in this folder.

## 1. `train_eval.py`: train and score the detector

The task is binary: is a flow an **attack** (Bot, PortScan or DDoS) or **BENIGN**? The 7 `UNCLEAR` flows
are dropped, leaving 536,649 flows: 274,962 benign, 161,201 PortScan, 95,683 DDoS and 4,803 Bot.

### Features

For every flow, the script computes one row of features from its **first N packets only** (N = 4 in the
main setting). Each feature is something a switch can keep per flow in a few registers: counters, sums,
minimum and maximum, first-packet values, and time differences in whole microseconds. No feature reads
the payload or needs a division.

| Group | Features |
|---|---|
| Behaviour (17) | packets in total, forward and backward; IP bytes forward and backward; smallest and largest packet; payload bytes forward and backward; number of packets with SYN, ACK, FIN, RST and PSH; duration; smallest and largest gap between packets |
| Port (2) | protocol and destination port |
| Fingerprint (3) | TTL and TCP window of the first packet, TCP window of the first reply; used only in the ablation |

### Models

- **Decision tree** of depth 6: this is the detector. A tree this small can be translated into a switch's
  match-action tables.
- **Random forest** of 100 trees: a reference for what a much larger model would add. It is not meant to
  run on a switch.

Both use seed 37.

### Splitting the data

- **Temporal split (main):** within each class, flows are sorted by start time; the earliest 70% train the
  model and the latest 30% test it. The model is always tested on a later stretch of each attack, so
  near-identical flows from the same burst cannot sit on both sides. The main test set has 82,489 benign,
  48,360 PortScan, 28,705 DDoS and 1,441 Bot flows.
- **Random split:** a stratified 70/30 split with seed 37, run only to show how much a random split
  inflates the scores.

### Scores

Attack flows count as positives. **Precision** is the share of flagged flows that really are attacks,
**recall** is the share of attack flows that get flagged, and the **false-positive rate (FPR)** is the
share of benign flows wrongly flagged. Recall is also reported for each attack type separately.

### Experiments

1. **Main:** N = 4, temporal split.
2. **Random split:** the same, with a random 70/30 split.
3. **Leave one attack out:** train without one attack type, then test on benign flows plus that attack, to
   see whether an attack the model has never seen is caught.
4. **Feature ablation:** drop the port features, or add the fingerprint features.
5. **Sweep over N:** the main setting for N = 1, 2, 3, 4, 6, 8, 12 and 16.

Results for N = 4:

| Setting | Model | Precision | Recall | FPR | Recall Bot | Recall PortScan | Recall DDoS |
|---|---|---|---|---|---|---|---|
| Main: temporal split | tree | 0.9985 | 0.9969 | 0.138% | 0.881 | 0.999 | 1.000 |
| Main: temporal split | forest | 1.0000 | 0.9971 | 0.004% | 0.881 | 0.999 | 1.000 |
| Random split | tree | 0.9988 | 0.9998 | 0.110% | 1.000 | 1.000 | 1.000 |
| No port features | tree | 0.9953 | 0.9972 | 0.445% | 0.881 | 0.999 | 1.000 |
| With fingerprint features | tree | 0.9986 | 0.9978 | 0.133% | 0.881 | 1.000 | 1.000 |
| Bot left out of training | tree | 0.9721 | 0.8128 | 0.136% | 0.813 | – | – |
| Bot left out of training | forest | 0.9992 | 0.8112 | 0.004% | 0.811 | – | – |
| PortScan left out of training | tree | 0.9998 | 0.9669 | 0.030% | – | 0.967 | – |
| PortScan left out of training | forest | 1.0000 | 0.0002 | 0.000% | – | 0.000 | – |
| DDoS left out of training | tree | 0.7949 | 0.0003 | 0.010% | – | – | 0.000 |
| DDoS left out of training | forest | 0.0000 | 0.0000 | 0.005% | – | – | 0.000 |

Sweep over N (tree, temporal split):

| N | 1 | 2 | 3 | 4 | 6 | 8 | 12 | 16 |
|---|---|---|---|---|---|---|---|---|
| Precision | 0.9392 | 0.9966 | 0.9845 | 0.9985 | 0.9986 | 0.9969 | 0.9981 | 0.9987 |
| Recall | 0.9985 | 0.9955 | 0.9831 | 0.9969 | 0.9967 | 0.9941 | 0.9971 | 0.9934 |
| FPR | 6.156% | 0.324% | 1.475% | 0.138% | 0.137% | 0.291% | 0.183% | 0.119% |

What the results show:
- The small tree catches almost as many attacks as the forest; the forest's advantage is fewer false
  alarms (FPR 0.004% against 0.138%).
- A random split flatters the model: Bot recall goes from 0.881 to 1.000 when near-identical flows can
  appear in both training and test data.
- An attack type missing from training is mostly missed. DDoS recall falls to 0.000 and Bot to about 0.81.
  An unseen PortScan is still caught by the tree (0.967) but not by the forest (0.000).
- Port features matter: without them the FPR is about three times higher.
- One packet is not enough (FPR 6.2%). Two packets already work well, three are worse than two (explained
  by `inspect_results.py`), and from four packets on the results stay about the same.


## 2. `inspect_results.py`: why the numbers come out this way

This script uses the same data, seed and tree settings as the main experiment, and prints five checks.

1. **What does the dominant feature look like?** Forward payload bytes in the first 4 packets: 98.6% of
   DDoS flows send exactly 20 bytes, the request of the attack tool (LOIC). 99.9% of PortScan flows and
   84.7% of Bot flows send 0 bytes. Benign values are spread out; the most common one covers only about
   4% of flows.
2. **Packets a switch would never see.** The capture machine merged TCP segments into "packets" larger
   than 1,500 bytes. Among the first 4 packets these are rare (0.5% of flows at most), but within the first
   16 they appear in 99.98% of DDoS flows and 10.5% of benign flows. Features built from many packets
   would partly learn this capture artefact, which is one reason the main setting uses N = 4.
3. **Which Bot flows does the main tree miss?** It misses 171 of the 1,441 Bot test flows. 159 of them are
   three-packet flows to port 8080 in which every packet carries SYN and none carries RST, which looks like
   a connection attempt being retried. All 1,270 caught flows have the usual two-packet SYN + RST shape.
   This is a case where the detector fails: the same bot, behaving slightly differently, slips through.
4. **Why is N = 3 worse than N = 2?** It is not drift over time: at N = 3, DDoS recall is similar in every
   fifth of the test period (0.96 to 0.98), and DDoS flow durations look the same in training and test.
   The cause is the TCP handshake. At N = 3, a flow's first three packets are SYN, SYN-ACK and ACK, so a
   normal web connection and a DDoS connection look the same. Benign false positives rise from 267 at
   N = 2 to 1,217 at N = 3, mostly on port 80 with exactly that handshake. At N = 4, the first data packet,
   LOIC's 20-byte request, separates them again.
5. **Precision if attacks were rarer.** The test set is about half attacks, which flatters precision. With
   the main tree's recall and FPR, precision would be 0.999 if half of all flows were attacks, 0.988 at 10%,
   0.879 at 1% and 0.419 at 0.1%.
