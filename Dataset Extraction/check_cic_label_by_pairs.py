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

    print(f"\n=== {name.split('/')[-1]}")
    print("  bot victim <-> 205.174.165.73 flows by CIC label:", df[bot]["Label"].value_counts().to_dict())
    if bot.any():
        benign_bot = df[bot & (df["Label"] == "BENIGN")]
        if len(benign_bot) > 0:
            first = benign_bot["Timestamp"].iloc[0]
            last = benign_bot["Timestamp"].iloc[-1]
            ports = benign_bot["Destination Port"].value_counts().head(3).to_dict()
            print("    BENIGN-labelled ones: time range", first, "...", last, "| dst ports:", ports)
        labelled_bot = df[bot & (df["Label"] == "Bot")]
        print("    dst ports of Bot-labelled:", labelled_bot["Destination Port"].value_counts().head(3).to_dict())

    print("  172.16.0.1 <-> 192.168.10.50 flows by CIC label:", df[attack]["Label"].value_counts().to_dict())
    benign_attack = df[attack & (df["Label"] == "BENIGN")]
    if len(benign_attack) > 0:
        minutes = benign_attack["Timestamp"].str.split(" ").str[1]
        print("    BENIGN-labelled ones, top minutes (12h clock):", minutes.value_counts().head(8).to_dict())
