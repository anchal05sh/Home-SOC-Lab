# Detection: LOLBin Outbound Network Connection (Sysmon Event ID 3)

## Summary

| Field | Value |
|---|---|
| Alert name | Sysmon - LOLBin Network Connection |
| Data source | Sysmon Event ID 3 (Network Connection) |
| Platform | Splunk Enterprise |
| Severity | Medium |
| Schedule | Every 5 minutes (cron `*/5 * * * *`), search window: last 5 minutes |
| Trigger | Number of results > 0, once |
| MITRE ATT&CK | T1218 Signed Binary Proxy Execution, T1105 Ingress Tool Transfer |

**Goal:** detect signed Windows binaries that are commonly abused by attackers (certutil, mshta, regsvr32, bitsadmin, wscript, cscript) making outbound network connections, which is rare in normal use.

## Lab architecture

- **Endpoint:** Windows 11 VM running Sysmon and the Splunk Universal Forwarder
- **SIEM:** Splunk Enterprise on an Ubuntu server
- **Index:** `sysmon`
- **Parsing:** Splunk Add-on for Sysmon (extracts `EventCode`, `Image`, `DestinationIp`, etc.)

```
Windows 11 VM (Sysmon -> Universal Forwarder) --9997--> Splunk Enterprise (Ubuntu)
```

## Data collection

**Sysmon config** (`sysmonconfig.xml`): logs all network connections, excluding Splunk's own processes.

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <NetworkConnect onmatch="exclude">
      <Image condition="end with">\Splunkd.exe</Image>
      <Image condition="end with">\splunk-winevtlog.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Forwarder input** (`inputs.conf` on the VM):

```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = sysmon
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

### Issue encountered: forwarder could not read the Sysmon log

The forwarder logged `Could not subscribe to Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational': errorCode=5` (access denied). The service runs as `NT SERVICE\SplunkForwarder`, which had no read access to the Sysmon channel.

**Fix:**

```
net localgroup "Event Log Readers" "NT SERVICE\SplunkForwarder" /add
Restart-Service SplunkForwarder
```

## Detection logic

```spl
index=sysmon EventCode=3 Initiated=true
| eval img=lower(Image)
| where like(img,"%\\certutil.exe") OR like(img,"%\\mshta.exe") OR like(img,"%\\regsvr32.exe") OR like(img,"%\\bitsadmin.exe") OR like(img,"%\\wscript.exe") OR like(img,"%\\cscript.exe")
| table _time host User Image DestinationIp DestinationPort
```

- `Initiated=true` limits results to outbound connections started by this host.
- `lower(Image)` handles path case differences (`System32` vs `system32` appear as different values in Splunk).

## Baseline

Before alerting, I listed all processes making outbound connections over 24 hours:

```spl
index=sysmon EventCode=3 Initiated=true
| stats count dc(DestinationIp) as unique_dests by Image
| sort - count
```

Top talkers were normal Windows and Microsoft processes (svchost.exe, msedge.exe, msedgewebview2.exe, MpDefenderCoreService.exe, OneDrive.exe). The LOLBin search returned **0 events** against this baseline, so it starts with no false positives.

## Validation

| Test | Result |
|---|---|
| Baseline LOLBin search, 24h | 0 events (expected) |
| `certutil -urlcache` download | Blocked by Windows ("Access is denied"), so no connection was made and nothing was logged. Prevention worked before detection had anything to see. |
| `bitsadmin /transfer` | No match: BITS hands the job to a service in `svchost.exe`, so Sysmon logged the connection under svchost.exe, not bitsadmin.exe |
| `cscript` running a script that requests example.com | Process start (Event ID 1) and exit (Event ID 5) only, with no DNS (22) or connection (3) logged, so nothing for the rule to match |
| Pipeline test using `powershell.exe` as a temporary stand-in in the search | Alert fired: scheduler logged `status=success, result_count=1`, and the alert appeared under Triggered Alerts |

The end-to-end path (Sysmon, forwarder, index, field extraction, scheduled alert, Triggered Alerts) was confirmed using the PowerShell stand-in, which was then removed from the final search. I did not get a direct LOLBin connection to trigger the final rule in this lab, so that remains an open validation item.

## Limitations and tuning notes

- **Coverage gap for BITS:** bitsadmin activity shows up as svchost.exe connections, so this rule won't catch it. Detecting it needs BITS client event logs.
- **Legitimate use:** wscript/cscript and regsvr32 can make legitimate connections in some environments. Tune with an allowlist on `DestinationHostname` or `User` if needed.
- **Context:** correlate with Event ID 1 on `ProcessGuid` to see the parent process and command line behind each connection (for example, a LOLBin spawned by Word or Excel would justify raising severity to High).
- **Scheduler load:** on this small lab server, some scheduled runs were skipped (`status=skipped`). The next run still caught the event, but a longer window or a 10-minute schedule is an option if skips continue.

## Next improvements

- Add a beaconing detection (regular-interval connections, T1071)
- Join Event ID 1 for parent process and command line
- Add Sysmon Event ID 22 (DNS) for domain-based context
