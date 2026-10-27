
# Datasets

Processed from the CIC-IDS2017 capture of Friday 7 July 2017.

| File | Rows | What it is |
|---|---|---|
| `friday_labelled.parquet` | 536,656 | One row per connection: addresses, ports, protocol, start and end time, total packets, and its label (BENIGN, Bot, PortScan, DDoS or UNCLEAR) |
| `friday_packets.parquet` | 3,282,716 | Header fields of the first 16 packets of each connection: time, direction, IP length, TTL, TCP flags, TCP window, payload length |

The raw 8.8 GB capture is not included because it exceeds GitHub's 100 MB file limit.
Source: https://www.unb.ca/cic/datasets/ids-2017.html

Citation: I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
