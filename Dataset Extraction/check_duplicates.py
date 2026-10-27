import sys
from collections import Counter
import dpkt
import numpy as np

path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/Friday-WorkingHours.pcap"
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 300000
