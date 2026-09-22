# Lab 05: Port Scan / Recon Detection via Windows Firewall Logs + Wazuh

## Objective
Extend the existing three-VM lab (Kali, Windows, Ubuntu/Wazuh) to simulate
a reconnaissance/port-scanning phase of an attack chain, and evaluate
whether Wazuh — using Windows Firewall logs as the data source instead of
Sysmon — can detect a port scan, either out of the box or via a custom
correlation rule.

## Environment
| Role | VM | Purpose |
|---|---|---|
| Attacker | Kali Linux | Port scanning (nmap) |
| Victim | Windows | Target endpoint, Windows Firewall logging enabled, Wazuh Agent installed |
| SIEM | Ubuntu | Wazuh Manager, Indexer, Dashboard |

All three VMs remained on the same VirtualBox Host-Only network used in
prior labs. Mid-lab, the Host-Only adapter itself was found to be
misconfigured on the host side (a link-local/APIPA address instead of a
proper private IP), which had been silently breaking host-to-VM
reachability; this was corrected as part of this lab.

## Detection Setup
Unlike Lab 03 (which relied on Sysmon), this lab uses **Windows Firewall
logging** as the primary data source, since Sysmon alone does not clearly
surface a scan pattern.

1. Enabled logging for the **active** network profile specifically
   (`Get-NetConnectionProfile` confirmed Public, not Domain/Private) via
   Windows Defender Firewall with Advanced Security → Properties → Public
   Profile → Logging:
   - Log dropped packets: Yes
   - Log successful connections: Yes
   - Log path: `%systemroot%\System32\LogFiles\Firewall\pfirewall.log`
2. Added a `<localfile>` block to the Windows agent's `ossec.conf` to
   forward this log to the manager (not monitored by default):
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>C:\Windows\System32\LogFiles\Firewall\pfirewall.log</location>
   </localfile>
   ```
3. Confirmed via `ossec.log` that the agent was actively analyzing the
   file after each config change/restart.

## Attack Simulation Steps
1. From Kali, ran a TCP connect scan against the Windows VM:
   `nmap -sT 192.168.56.102`
2. Result: 1000 scanned ports, all in a **filtered** state (Windows
   Firewall silently dropping SYN packets with no response) — confirming
   the scan traffic reached the host and was being blocked.
3. Repeated the scan multiple times over the course of the lab to test
   detection under varying conditions.

## Detection Results

| Layer | Result |
|---|---|
| `pfirewall.log` (local, Windows) | DROP entries correctly logged for every scanned port |
| Wazuh default rule `4101` ("Firewall drop event", level 5) | Correctly parsed and matched every DROP line — but has `<options>no_log</options>` by design, so individual drops never write to `alerts.json` (visible only in `archives.json` with `logall` enabled) |
| Wazuh default rule `4151` ("Multiple Firewall drops from same source", level 10, frequency=10/timeframe=45s, `same_source_ip`) | **Confirmed working** on unrelated background traffic (an SSDP/UPnP UDP flood to `239.255.255.250:1900`) — but **did not fire** for the nmap scan traffic, despite the scan producing 11+ drop events within a ~31 second window, comfortably inside the rule's stated threshold |
| Custom rule `100100` (identical frequency/timeframe structure to 4151, written and loaded successfully into `local_rules.xml`) | Also did not reliably fire during testing |

## Key Finding
Windows Firewall logging and Wazuh's parsing/decoding of that log are both
working correctly — individual firewall drop events are consistently and
accurately parsed into structured fields (`srcip`, `dstip`, `srcport`,
`dstport`) by Wazuh's default `windows-date-format` decoder.

However, the **frequency/timeframe-based correlation** that Wazuh relies
on to turn "many individual drops" into "one port-scan alert" proved
unreliable in this environment. This was tested two ways:

- Wazuh's own built-in rule `4151` fired correctly for one traffic
  pattern (a UDP flood to a single port) but not for another (a TCP
  connect scan across many ports) — even though both patterns produced
  well more than the required event count within the required time
  window.
- A custom rule (`100100`) built with an identical structure to `4151`,
  correctly loaded by the manager with no syntax errors, showed the same
  inconsistent behavior.

Extended troubleshooting also surfaced a related, likely contributing
issue: the Windows agent's file-based log monitoring (used for
`pfirewall.log`, as opposed to the Event Log API used for Sysmon/Security
channels) tracks a byte-offset read position per file.

**Conclusion:** the root cause was not fully isolated within this
session. It sits somewhere between (a) how Wazuh's rule engine evaluates
frequency/timeframe correlation against real-world event timing, and (b)
an apparent fragility in file-based (non-eventchannel) log monitoring on
the Windows agent under repeated service restarts. Given the time already
invested (3+ days) without full resolution, this is documented as an open
finding rather than pursued further in this session.

## Why This Matters
This is arguably a more operationally significant gap than Lab 03's. A
missed individual event (like a single C2 callback) is bad, but a missed
**correlation** — the mechanism specifically designed to turn "noise" into
"signal" — undermines the core value proposition of a SIEM. If a stack
correctly logs and parses every individual drop but cannot reliably
aggregate them into a scan alert, an analyst gets no actionable signal at
all during actual reconnaissance activity, despite the raw data being
present the whole time.

It's also a useful, honest data point on tooling reliability under
real-world conditions (repeated restarts, evolving config, a
resource-constrained lab VM) rather than a clean, undisturbed reference
install — which is closer to what a real production environment
tolerates than a lab is usually given credit for.

## Next Steps
- Rebuild this same detection scenario (Windows Firewall logging → port
  scan detection) against **Splunk** instead, as a direct comparison
  point for correlation/alerting reliability between the two platforms.
- If returning to Wazuh: test rule `4151`/`100100` behavior against a
  freshly provisioned agent (no restart history) to isolate whether the
  correlation failures are inherent to the rule engine or specific to
  accumulated state on this agent.
- Investigate Wazuh's `logcollector` file-offset tracking behavior
  further — specifically whether it's expected to survive a service
  restart without manual intervention, and whether this is documented
  behavior or a bug.
- Consider `eventchannel`-based Windows Firewall log collection (via the
  "Windows Firewall With Advanced Security" operational log, which
  Windows also writes to natively) as an alternative to raw file-tailing,
  since eventchannel-based sources did not exhibit the same forwarding
  issues in this lab.
