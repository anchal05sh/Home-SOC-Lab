
# Home SOC Lab

Ongoing detection-engineering lab — setting up a SOC monitoring stack, simulating attack scenarios, and documenting each one as an incident report.

## Stack

- SIEM:** Wazuh -> Splunk (manager + indexer + dashboard)
- Virtualization:** VirtualBox
- Endpoint:** Windows 11 VM (agent)
- Manager OS:** Ubuntu Server 24.04 LTS
- Attacker - Kali Linux


## Labs

| # | Lab | Focus | Report |
|---|-----|-------|--------|
| 01 | Brute-Force Detection | Simulated failed logins, validated detection rules | [reports/lab01-brute-force.md](reports/lab01-brute-force-detection.md) |
| 02 | EICAR / FIM Test | File Integrity Monitoring validation | [reports/lab02-eicar-fim.md](reports/lab02-eicar-detection-test.md) |
| 03 | Sysmon + Wazuh C2 Detection | Full attack chain (payload delivery → execution → C2 callback) via Metasploit, isolated 3-VM lab; identified a detection gap in Wazuh's handling of Sysmon Event ID 3 (network connections) | [reports/lab03-sysmon-wazuh-c2-detection.md](reports/lab03-sysmon-wazuh-c2-detection.md) |
| 04 | Ping Flood Detection via Packet Capture Analysis | Network-based DoS detection | [reports/lab04-ping-flood-detection.md](reports/lab04-ping-flood-detection.md)|
| 05 | Port Scan Detection | Reconnaissance phase simulation | [reports/lab05-port-scan-detection.md](reports/lab05-port-scan-detection.md)|
| 06 | Splunk Setup and failed login detection | Splunk setup & testing |[lab06-splunk-setup-and-failed-login-detection.md](reports/lab06-splunk-setup-and-failed-login-detection.md)
| 07 | LOLBin Detection | Detecting LOLBin Network Connections with Sysmon Event ID 3 and Splunk |[lab07-reports/lab07-sysmon-eid3-lolbin-detection.md](reports/lab07-sysmon-eid3-lolbin-detection/README.md)


## Structure

```
reports/   → written incident reports for each lab
scripts/   → simulation scripts used to trigger detections
configs/   → relevant Splunk rule configs / rule IDs used
docs/      → setup and environment notes
```

## Notes

All activity in this repo is self-generated in a controlled home lab for detection-validation purposes — no real/malicious activity involved.
