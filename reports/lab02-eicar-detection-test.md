# Lab 02: EICAR Test File Detection

**Endpoint:** WINDOWS11 (Agent ID: 002)

## 1. Test Objective

Validate end-to-end detection capability of the Wazuh SIEM deployment using the industry-standard EICAR test file, confirming that file system events on a monitored endpoint are correctly captured, forwarded, and alerted on by the SIEM.

## 2. Environment

| Field | Value |
|---|---|
| SIEM Platform | Wazuh v4.14.7 |
| Manager OS | Ubuntu Server 24.04 LTS |
| Monitored Endpoint | Windows 11 Home |
| Agent Name | WINDOWS11 (Agent ID: 002) |
| Agent Version | Wazuh v4.14.7 |
| Detection Module | File Integrity Monitoring (FIM / syscheck) |
| Test Date | Aug 3, 2026 |

## 3. Test Procedure

1. Generated the standard EICAR test string on the monitored Windows endpoint and wrote it to a file inside a Wazuh-monitored directory (`Startup` folder).
2. Windows Defender's real-time protection intercepted and removed the file immediately on the first attempt, confirming endpoint AV was functioning correctly. A temporary Defender exclusion was applied to the target directory to let the file persist long enough for FIM to evaluate it, then removed immediately after the test.
3. Triggered an on-demand FIM scan on the agent from the manager to avoid waiting for the default 12-hour scheduled scan interval.
4. Reviewed detection results in the Wazuh dashboard under File Integrity Monitoring → Events for the WINDOWS11 agent.

## 4. Result: DETECTED (PASS)

| Field | Value |
|---|---|
| Timestamp | Aug 3, 2026 @ 15:04:26.597 |
| Agent | WINDOWS11 |
| Syscheck event | added |
| Rule description | "File added to the system" |
| Rule ID | 554 |
| Rule level | 5 |

## 5. Analysis / Conclusion

The test confirms full pipeline integrity across the monitoring stack: endpoint file event → Wazuh agent (syscheck) → Wazuh manager → rule correlation → dashboard visibility. The Windows agent is actively connected and reporting, and File Integrity Monitoring is functioning as expected on the rebuilt SIEM environment.

## 6. Recommended Next Steps

- Remove the temporary Windows Defender exclusion if not already removed, to restore full endpoint protection.
- Run a Vulnerability Detection test (outdated software CVE check) to validate the second detection module.
- Clean up the stale/disconnected duplicate agent entry from the manager's agent list.
- Consider enabling real-time (`realtime="yes"`) monitoring on additional directories of interest for faster detection outside the default scan interval.

---
*Part of an ongoing home SOC lab — see repo README for the full lab index.*
