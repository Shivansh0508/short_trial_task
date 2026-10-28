
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
