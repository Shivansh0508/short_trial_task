import sys
import zipfile
import pandas as pd
zip_path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/labels/GeneratedLabelledFlows.zip"
bot_server = "205.174.165.73"
bot_victims = ["192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"]
attacker = "172.16.0.1"
victim = "192.168.10.50"
z = zipfile.ZipFile(zip_path)
for name in z.namelist():
    if "Friday" not in name:
        continue

    df = pd.read_csv(z.open(name))
    df.columns = df.columns.str.strip()
    df = df.dropna(subset=["Label"])
    src = df["Source IP"]
    dst = df["Destination IP"]
    bot = (src.isin(bot_victims) & (dst == bot_server)) | (dst.isin(bot_victims) & (src == bot_server))
    attack = ((src == attacker) & (dst == victim)) | ((src == victim) & (dst == attacker))

