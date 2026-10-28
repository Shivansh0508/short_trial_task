
Notes: understanding the pipeline

> These notes were written with help from an AI assistant (Claude). 

## Step 1: How Bot, PortScan and DDoS differ in their first 4 packets

- **Bot** (flow 379511, 192.168.10.8 → 205.174.165.73, port 8080): only **2 packets**. The infected PC sends SYN; the attacker's server answers RST-ACK about 0.7 ms later. No data. The bot is trying to reach its command server, which refuses the connection.
- **PortScan** (flow 260663, 172.16.0.1 → 192.168.10.50, port 10626): only **2 packets**, SYN then RST-ACK, about 0.05 ms apart. No data. The port is closed, so the scanner moves on to the next port.
- **DDoS** (flow 505139, 172.16.0.1 → 192.168.10.50, port 80): a full handshake (SYN, SYN-ACK, ACK), then **one small packet carrying 20 bytes of data**, all within about 1 ms.

**Takeaway:** Bot and PortScan look almost identical; the main difference is the port. DDoS looks like a normal web visit except for its tiny message and its speed.

## Step 2: Why CIC's labels can't be used as-is

- Connections between the 5 infected PCs and the command server (port 8080) are labelled **Bot** in the morning file (1,962) but **BENIGN** in the afternoon files: **350** (DDoS file) + **623** (PortScan file) = **973**. Same machines, same port, same rhythm; only the file changed.
- During the DDoS, 31,340 attacker ↔ victim connections are labelled BENIGN, plus 960 during the scans.
- Timestamps use a 12-hour clock without AM/PM, to the minute only ("3:56" means 15:56).
- The spreadsheet's numbers are computed over whole connections, and its tool cuts traffic into connections differently (about 159,000 rows vs our 95,683 DDoS connections), so its labels can't be copied one-to-one.

**So:** labels were re-applied from CIC's published attack schedule, and the spreadsheet was used only as a cross-check.

## Step 3: Two surprises in the raw capture

- The file is named `.pcap` but is really **pcapng**. The first attempt to read it failed with "invalid tcpdump header", and the first bytes of the file showed the pcapng signature.
- Some packets were recorded **twice**. In the first 300,000 packets, **6.5%** are exact copies, usually **4 µs** after the original and with the same TTL. A router would lower the TTL, so the copies come from the capture setup, not from the network. They appear only between machines inside the office network, where about half of all packets are copies.
- A switch would see each packet once, so copies that arrive within 1 ms are dropped: **413,907** packets over the whole day.

**Takeaway:** check the raw data before trusting it. Without this step, connections inside the office network would show twice as many packets as they really have.

## Step 4: From packets to connections

- A **connection** (flow) is all packets between the same two endpoints (IP address and port) with the same protocol, in either direction. The machine that sends the first packet is the initiator.
- A connection ends after **120 s** of silence, or when a new SYN arrives after it was closed with FIN or RST.
- Only the header fields of the **first 16 packets** of each connection are kept; later packets are just counted. A switch has to decide early and has little memory per connection, so the detector may only look at the start.
- Result: **9,997,874** packets became **536,656** connections and **3,282,716** stored packets.

**Takeaway:** everything after this point works on connections and their first few packets, never on whole conversations.

## Step 5: What the detector looks at, and how it is tested

- **Features** come from the first N packets of a connection (N = 4 in the main setting): how many packets go each way, their sizes, payload bytes each way, how many carry SYN, ACK, FIN, RST or PSH, the duration and the gaps between packets, plus the protocol and destination port. A switch can keep all of these in a few counters: nothing reads the payload and nothing needs division.
- **Model:** a decision tree of depth 6, small enough to turn into a switch's match-action table. A random forest of 100 trees is trained too, only to see how much a much bigger model would gain.
- **Testing:** within each label, the earliest 70% of connections are used for training and the latest 30% for testing. A random split would put near-identical connections from the same burst on both sides and inflate the scores: Bot recall jumps from 0.881 to 1.000.

**Takeaway:** the test is deliberately strict. The model is always tested on a later part of each attack than it trained on.

## Step 6: Results

- Main tree (N = 4): precision **0.9985**, recall **0.9969**, false-positive rate **0.138%**. Recall per attack: Bot 0.881, PortScan 0.999, DDoS 1.000.
- The forest catches the same share of attacks but raises far fewer false alarms (0.004%).
- One feature does almost all the work: **payload bytes sent by the initiator** (importance 0.91). 98.6% of DDoS connections send exactly 20 bytes, while 99.9% of port-scan and 84.7% of Bot connections send none. That is the difference already visible in Step 1.

**Takeaway:** the tree mostly learned "how much data did the initiator send in its first 4 packets?"

## Step 7: How many packets are needed

- With **1 packet**, 6.2% of benign connections are flagged. With **2**, the results are already good. From **4** on, they barely change.
- **3 packets are worse than 2.** The first three packets of any TCP connection are the handshake (SYN, SYN-ACK, ACK), so a normal web visit and a DDoS connection look the same. False alarms jump from 267 to 1,217, mostly on port 80. It is not a change over time: DDoS recall is similar in every part of the test period, and DDoS durations look the same in training and test. At 4 packets, LOIC's 20-byte request separates them again.
- Going higher has a hidden cost. The capture machine merged TCP segments into "packets" larger than 1,500 bytes, which a switch never sees. They are rare in the first 4 packets (0.5% of connections at most) but appear in 99.98% of DDoS connections by packet 16.

**Takeaway:** N = 4 is the first setting that gets past the handshake, and it is still early enough to avoid the capture artefacts.

## Step 8: Where the detector fails

- **An attack it has never seen.** Trained without DDoS, the tree catches none of the DDoS connections (recall 0.000); trained without Bot, it catches 0.81 of Bot. An unseen PortScan is still caught by the tree (0.967) but not by the forest (0.000).
- **A known attack behaving a little differently.** The tree misses 171 of the 1,441 Bot test connections. 159 of them are three-packet connections where every packet carries SYN and none carries RST, which looks like a retried connection attempt. The tree learned the usual SYN followed by RST from Step 1.
- **Real networks have far fewer attacks.** About half of the test set is attacks. With the same recall and false-positive rate, precision would be 0.879 if 1% of connections were attacks, and 0.419 at 0.1%, so more than half of the alarms would be false.

**Takeaway:** the detector recognises the attacks it was trained on, as they behaved on this one day. It is not a general attack detector.
