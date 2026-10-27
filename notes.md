
Notes: understanding the pipeline

> These notes were written with help from an AI assistant (Claude). 

## Step 1: How Bot, PortScan and DDoS differ in their first 4 packets

- **Bot** (flow 379511, 192.168.10.8 → 205.174.165.73, port 8080): only **2 packets**. The infected PC sends SYN; the attacker's server answers RST-ACK about 0.7 ms later. No data. The bot is trying to reach its command server, which refuses the connection.
- **PortScan** (flow 260663, 172.16.0.1 → 192.168.10.50, port 10626): only **2 packets**, SYN then RST-ACK, about 0.05 ms apart. No data. The port is closed, so the scanner moves on to the next port.
- **DDoS** (flow 505139, 172.16.0.1 → 192.168.10.50, port 80): a full handshake (SYN, SYN-ACK, ACK), then **one small packet carrying 20 bytes of data**, all within about 1 ms.

**Takeaway:** Bot and PortScan look almost identical; the main difference is the port. DDoS looks like a normal web visit except for its tiny message and its speed.
