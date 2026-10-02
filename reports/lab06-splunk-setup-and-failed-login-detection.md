# Lab 06 – Splunk Setup and Baseline Failed-Login Detection

## Objective
Set up Splunk as the lab's new SIEM (replacing Wazuh) and validate the log pipeline by detecting a simulated failed SMB login from an attacker VM.

## Environment
| Component | Role |
|---|---|
| Ubuntu Server | SIEM host — runs Splunk (same host previously running Wazuh) |
| Windows VM | Victim / log source — runs Splunk Universal Forwarder |
| Kali VM | Attacker — generated the failed SMB login |
| Network | Isolated host-only lab network |

*(Fill in: Splunk Enterprise version, VM IPs, e.g. static IPs and port 9997 open.)*

## Methodology
1. **SIEM install:** Installed Splunk on the Ubuntu server and enabled receiving on port 9997. *(Confirm port.)*
2. **Forwarder:** Installed the Universal Forwarder on the Windows VM and pointed it at the Splunk server.
3. **Log collection:** Configured collection of Windows Security logs, e.g. via `inputs.conf`. *(Confirm method.)*
4. **Network setup:** Configured lab network settings so the Kali, Windows, and Ubuntu VMs could communicate on the isolated network, including connectivity between the Windows forwarder and the Splunk server.
5. **Attack simulation:** From Kali, ran a failed login attempt against the Windows VM using `smbclient`, entering an incorrect password.
6. **Detection:** Searched Splunk for the resulting events.

## Detection Query
**Log source / Event ID:** Windows Security Event ID 4625 (failed logon)

```bash
smbclient //<victim-ip>/<share> -U <username>
```

```spl
index="windows" EventCode=4625
```

## Results
*(Fill in: screenshot or raw event output from Splunk.)*

- Time for the failed login to appear in Splunk: _TBD_
- Event details captured (source IP, account name, logon type, failure reason): _TBD_
- Detected via search without custom rules: Yes

## Findings
The failed SMB login from Kali was picked up by the forwarder and was visible in Splunk without needing any custom rules, confirming the Universal Forwarder → Splunk pipeline works end to end. Compared to Wazuh, the Splunk interface felt clearer and easier to navigate, and searching and viewing events felt noticeably faster. This is a subjective impression from this lab setup, not a formal benchmark. Splunk is now installed and delivering Windows logs, which establishes the base for future Splunk-based detection labs.

## Limitations
- Single manual attempt, not a sustained brute-force pattern.
- No alert or threshold configured yet; detection was by manual search/dashboard.
- Wazuh vs. Splunk comparison is based on impression only, with no measured search times.

## Next Steps
- Create a saved alert for repeated 4625 events from one source.
- Add Sysmon logs to Splunk via the forwarder.
- Re-create earlier Wazuh labs (brute-force, EICAR/FIM) in Splunk for comparison.
- Map to MITRE ATT&CK T1110 (Brute Force).
