import argparse
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument("flows")
parser.add_argument("--out", required=True)
args = parser.parse_args()
attacker = "172.16.0.1"
victim = "192.168.10.50"
bot_server = "205.174.165.73"
bot_victims = ["192.168.10.5", "192.168.10.8", "192.168.10.9", "192.168.10.14", "192.168.10.15"]
