# Dataset Extraction

> @notes from AI

These six scripts turn the raw CIC-IDS2017 Friday capture into the labelled flow dataset in `datasets/`,
which the detector is trained on. They are numbered in the order they run; scripts 2, 3 and 4 each read
the previous one's output.

## 1. `check_duplicates.py`: are some packets recorded twice?

While testing the extractor, the same packet sometimes appeared twice inside one flow. This script
measures how often that happens.

- It reads the first N packets (default 300,000) and gives each TCP/UDP packet a signature: IP
  addresses, IP ID, protocol, ports, TCP sequence number, length and flags. A signature seen before
  counts as a repeat.
- It reports how far apart the copies are, whether their TTL matches, and which host pairs they come from.

Findings:
- 6.5% of packets are exact repeats, typically 4 µs apart; 99.17% arrive within 1 ms of the original.
- Every copy has the same TTL as the original, so the copies come from the capture setup, not a router.
- Copies occur only between hosts inside the LAN, where about half of all packets are repeats.
  Internet traffic has none.

LAN traffic was recorded twice. A switch on the path would see each packet once, so `extract_first.py`
removes copies that arrive within 1 ms.

## 2. `extract_first.py`: from packets to flows

This is the main dataset builder. For every packet in the capture, it:

1. Keeps only IPv4 TCP and UDP, and skips IP fragments.
2. Drops capture duplicates: a packet whose IP header and first 16 bytes of TCP/UDP header exactly match
   a packet seen less than 1 ms earlier.
3. Assigns the packet to a **flow**: the same two endpoints (IP address and port) and protocol, in either
   direction. The host that sends the first packet is the initiator.
4. Starts a new flow when the endpoints have been silent for more than 120 s, or (TCP only) when a new
   SYN arrives after the connection was closed with FIN or RST.
5. Stores the header fields of the **first 16 packets** of each flow. Later packets are only counted.

Only the first packets are kept because the detector has to decide early, from the first few packets of
a flow, as a switch would. The model then uses the first N of these 16 (N = 4 in the main experiment)
without re-reading the capture.

Options: `--k` (packets kept per flow, default 16), `--idle-timeout` (default 120 s), `--dup-window`
(default 0.001 s), `--max-packets` (stop early, for testing). The CIC file is named `.pcap` but is
actually in pcapng format, and the script reads either format.

Result on the full capture: 9,997,874 packets read, giving **536,656 flows** and **3,282,716 stored
packets**. Removed or skipped: 413,907 capture duplicates, 82,194 non-IPv4 frames, 1,144 packets of
other IP protocols and 196 IP fragments.

`friday_flows.parquet`, one row per flow:

| Column | Meaning |
|---|---|
| `flow_id` | 0, 1, 2, … in the order each flow's first packet arrived |
| `src_ip`, `src_port` | the initiator (sent the first packet) |
| `dst_ip`, `dst_port` | the responder |
| `proto` | 6 = TCP, 17 = UDP |
| `start_ts`, `last_ts` | time of the first and last packet (Unix time, seconds) |
| `n_pkts_total` | packets in the whole flow, after duplicate removal |

`friday_packets.parquet`, one row per stored packet:

| Column | Meaning |
|---|---|
| `flow_id` | the flow the packet belongs to |
| `idx` | position in the flow; 0 is the first packet |
| `ts` | packet time (Unix time, seconds) |
| `dir` | 0 = initiator to responder, 1 = reply |
| `ip_len` | IP total length in bytes |
| `ttl` | IP time-to-live |
| `tcp_flags`, `tcp_win` | TCP flags and window size (0 for UDP) |
| `payload_len` | bytes after the TCP/UDP header, taken from the header length fields |

## 3. `labels_flows.py`: label every flow

Labels come from the published attack schedule: which hosts talked, and when the flow started (local
time, ADT = UTC−3).

| Label | Rule | Flows |
|---|---|---|
| Bot | a bot victim (192.168.10.5, .8, .9, .14, .15) ↔ C&C server 205.174.165.73, any time | 4,803 |
| PortScan | 172.16.0.1 ↔ 192.168.10.50, starting between 13:00 and 15:40 | 161,201 |
| DDoS | 172.16.0.1 ↔ 192.168.10.50, starting between 15:40 and 16:30 | 95,683 |
| UNCLEAR | 172.16.0.1 ↔ 192.168.10.50 outside both windows; left out of training and testing | 7 |
| BENIGN | everything else | 274,962 |

Why these rules:
- 172.16.0.1 is the firewall's inside address. The attack machines sit behind it (NAT), so in the
  capture all PortScan and DDoS traffic comes from 172.16.0.1.
- The bot keeps contacting its C&C server until the end of the day, long after the published 10:02–11:02
  window, so Bot is labelled by host pair alone.
- The last scan flow starts at 15:23 and the first DDoS flow at 15:56, so 15:40 separates the two.

The output is `friday_flows.parquet` with a `label` column added.

## 4. `check_labels.py`: compare with CIC's labels, minute by minute

CIC built its labels with a different flow tool (CICFlowMeter), so flow totals cannot match exactly,
but the timing of each attack should. The script counts attack flows per minute in both sources,
prints the totals and the minutes that only one side marks as attack, saves the per-minute counts to a
CSV and plots one panel per attack with the published schedule shaded.

CIC writes times on a 12-hour clock without AM/PM ("3:56" means 15:56). The capture runs from 08:59 to
17:02, so hours 1–7 are treated as afternoon.

| Attack | Flows here | Flows in CIC | Minutes here | Minutes in CIC | Minutes in both |
|---|---|---|---|---|---|
| Bot | 4,803 | 1,966 | 366 | 163 | 161 |
| PortScan | 161,201 | 158,930 | 33 | 27 | 27 |
| DDoS | 95,683 | 128,027 | 21 | 21 | 21 |

Every minute that CIC marks as PortScan or DDoS is also marked here, and this labelling adds 6 PortScan
minutes that CIC does not mark. Bot differs because CIC stops labelling the bot's traffic as Bot after
about 13:00 (see `check_cic_label_by_pairs.py`).

## 5. `check_cic_label_by_pairs.py`: how CIC labels the two key host pairs

For each Friday CSV, the script counts CIC's labels for the bot pair and for the attacker ↔ victim pair,
and shows the times and ports of the flows that CIC calls BENIGN.

| CIC file | Bot victims ↔ C&C server | 172.16.0.1 ↔ 192.168.10.50 |
|---|---|---|
| Morning | 1,962 Bot | 14 BENIGN (11:47–12:38) |
| Afternoon, PortScan | 623 **BENIGN**, port 8080 | 158,930 PortScan, 960 **BENIGN** |
| Afternoon, DDoS | 350 **BENIGN**, port 8080 | 128,027 DDoS, 31,340 **BENIGN** (mostly 16:06–16:15) |

CIC's labels are inconsistent. The same bot traffic to port 8080 is Bot in the morning file and BENIGN in
both afternoon files, and 31,340 attacker ↔ victim flows in the middle of the DDoS attack are BENIGN.
This is why the labels here are built from the schedule rather than taken from CIC's CSVs.

## 6. `make_sample_pcap.py`: a small capture for Wireshark

Picks 3 random flows from each label (seed 37) and copies the first 8 packets of each, byte for byte,
into a small pcap. A text listing next to it shows each packet's time since the flow started, its
direction, IP length and TCP flags. Result: 55 packets from 12 flows. Packets are copied as captured,
so capture duplicates still appear in the sample, while "packets in total" in the listing is counted
after duplicate removal.
