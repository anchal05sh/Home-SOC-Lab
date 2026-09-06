# Lab 04 – Ping Flood Detection via Packet Capture Analysis

## Objective
Simulate a basic ICMP (ping) flood between two VMs, capture the traffic with Wireshark, and write a Python script to analyze the traffic and flag a source IP as suspicious if its packet count exceeds a defined threshold.

## Environment
| Component | Role |
|---|---|
| Ubuntu VM | Traffic generator — sent a ping flood |
| Kali VM | Capture host — ran Wireshark to record incoming traffic |
| Threshold | 30 packets per source IP |

*(Fill in: VM IPs, hypervisor/network mode — e.g. host-only or NAT, and ping command used, e.g. `ping -f` or a loop.)*

## Methodology
1. **Traffic generation:** From the Ubuntu VM, initiated a ping flood targeting the Kali VM.
2. **Capture:** On the Kali VM, used Wireshark to capture the incoming ICMP traffic.
3. **Export:** Exported the capture to CSV (including an `ip.src` column) rather than parsing the raw `.pcap` directly.
4. **Analysis:** Wrote a Python script that reads the CSV with `csv.DictReader`, tallies packets per source IP using `collections.Counter`, prints total traffic volume per IP, then flags any IP whose count exceeds the threshold (30) as suspicious.

## Script
```python
import csv
from collections import Counter

THRESHOLD = 30
ip_counter = Counter()

with open("traffic.csv", newline="") as csvfile:
    reader = csv.DictReader(csvfile)

    for row in reader:
        src_ip = row.get("ip.src")

        if src_ip:
            ip_counter[src_ip] += 1

print("Traffic volume per source IP:\n")

for ip, count in ip_counter.items():
    print(f"{ip}: {count} packets")

print("\n[!] Potentially suspicious IPs:\n")
for ip, count in ip_counter.items():
    if count > THRESHOLD:
        print(f"{ip}: {count} packets (suspicious/above threshold)")
```

## Results
*(Fill in: contents of `traffic.csv` export, full script output — traffic volume per IP and which IP(s) were flagged.)*

- Total unique source IPs seen: _TBD_
- Packet count from the flooding IP: _TBD_
- Flagged as suspicious (>30): _Yes/No_

## Findings
Exporting the Wireshark capture to CSV and tallying per-IP packet counts with `Counter` is a lightweight way to surface a high-volume source without needing a pcap-parsing library like Scapy. Because the flood sends a large burst of ICMP requests from a single source, that IP's count separates clearly from normal background traffic once past the threshold. This mirrors, in a simplified/offline form, what a SIEM threshold rule (e.g. in Wazuh) does in real time.

## Limitations
- Static threshold (30) is arbitrary and untuned to a real baseline — a burst of legitimate pings or monitoring traffic could false-positive, and a slow/low-rate flood would stay under it.
- Counts total packets over the whole capture window, with no time dimension — no way to distinguish "30 packets in 1 second" from "30 packets over an hour."
- Relies on a manual CSV export step from Wireshark rather than parsing the pcap programmatically, so it isn't automated end-to-end.
- Only inspects `ip.src`; doesn't consider packet type/protocol distribution, so it would also flag any high-volume source, not specifically ICMP floods.

## Next Steps
- Parse the `.pcap` directly with Scapy (`rdpcap`) or PyShark to remove the manual CSV export step.
- Add a time-window/rate component (packets per second) instead of a flat total, to better approximate real flood detection and reduce false positives.
- Feed the same capture into Wazuh to compare this script's output against a SIEM-native threshold rule.
- Re-run with a lower-rate flood to test whether 30 is still an effective cutoff.
