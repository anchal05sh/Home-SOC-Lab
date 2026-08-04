
# Home SOC Lab

Ongoing detection-engineering lab — setting up a SOC monitoring stack, simulating attack scenarios, and documenting each one as an incident report.

## Stack

- SIEM:** Wazuh (manager + indexer + dashboard)
- Virtualization:** VirtualBox
- Endpoint:** Windows 11 VM (agent)
- Manager OS:** Ubuntu Server 24.04 LTS
- Simulation tooling:** PowerShell
- Attacker - Kali Linux

## Lab Index

| # | Title | Focus | Report |
|---|---|---|---|
| 01 | Brute-Force Authentication Attempt | Detecting repeated failed logons, account lockout correlation | [reports/lab01-brute-force-detection.md](reports/lab01-brute-force-detection.md) |
| 02 | EICAR Test File Detection | File Integrity Monitoring (FIM) validation | [reports/lab02-eicar-detection-test.md](reports/lab02-eicar-detection-test.md) |
| 03 | Coming soon | — | — |

## Structure

```
reports/   → written incident reports for each lab
scripts/   → simulation scripts used to trigger detections
configs/   → relevant Wazuh rule configs / rule IDs used
docs/      → setup and environment notes
```

## Notes

All activity in this repo is self-generated in a controlled home lab for detection-validation purposes — no real/malicious activity involved.
