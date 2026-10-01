\# Lab06: Splunk Setup and Baseline Failed-Login Detection



\## 1. Objective

Set up Splunk as the lab's new SIEM (replacing Wazuh) and validate the log pipeline by detecting a simulated failed SMB login from an attacker VM.



\## 2. Environment

| Component | Details |

|---|---|

| SIEM | Splunk \[Enterprise, version] on Ubuntu Server (same host previously running Wazuh) |

| Log source | Windows victim VM with Splunk Universal Forwarder |

| Attacker | Kali Linux VM |

| Network | Isolated host-only lab network |



\## 3. Methodology

1\. Installed Splunk on the Ubuntu server and \[enabled receiving on port 9997].

2\. Installed the Universal Forwarder on the Windows VM and pointed it at the Splunk server.

3\. Configured collection of \[Windows Security logs, e.g. via inputs.conf].

4\. From Kali, ran a failed login attempt against the Windows VM using `smbclient`:

```bash

&#x20;  smbclient //<victim-ip>/<share> -U <username>

```

&#x20;  (entered an incorrect password)

5\. Searched Splunk for the resulting events.



\## 4. Detection Logic

\*\*Log source / Event ID:\*\* Windows Security Event ID 4625 (failed logon)



```spl

index="windows" EventCode=4625

```



\## 5. Results

\- The failed login appeared in Splunk within \[X seconds/minutes].

\- Event details showed \[source IP, account name, logon type, failure reason].





\## 6. Observations

\- Configured the lab network settings so the Kali, Windows, and Ubuntu VMs could communicate on the isolated network, including connectivity between the Windows forwarder and the Splunk server. \[Add specifics if you want, e.g. static IPs, port 9997 open.]

\- The failed SMB login from Kali was picked up by the forwarder and visible in Splunk without needing any custom rules.

\- \*\*Compared to Wazuh:\*\* the Splunk interface is clearer and easier to navigate, and searching and viewing events felt noticeably faster. (Subjective impression from this lab setup, not a formal benchmark.)



\## 7. Limitations

\- Single manual attempt, not a sustained brute-force pattern.

\- No alert or threshold configured yet; detection was by manual search/dashboard.



\## 8. Next Steps

\- \[ ] Create a saved alert for repeated 4625 events from one source.

\- \[ ] Add Sysmon logs to Splunk via the forwarder.

\- \[ ] Re-create earlier Wazuh labs (brute-force, EICAR/FIM) in Splunk for comparison.

\- \[ ] Map to MITRE ATT\&CK T1110 (Brute Force).



\## 9. Conclusion

Splunk is installed, the Universal Forwarder is delivering Windows logs, and a simulated failed SMB login from Kali was successfully detected. This establishes the base for future Splunk-based detection labs.

