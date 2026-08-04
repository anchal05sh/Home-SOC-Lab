# Lab 01: Brute-Force Authentication Attempt Detected on Windows Endpoint

**Host:** windows11-client

## 1. Summary

Brute-force authentication attempt detected on Windows endpoint `windows11-client` via repeated failed logon attempts against the `administrator` account.

## 2. Detection Details

| Field | Value |
|---|---|
| Date/Time | Aug 4, 2026, 20:03:54 – 20:04:44 UTC |
| Source | Wazuh SIEM, Agent: `windows11-client` |
| Rules Triggered | Rule 6012x (Logon Failure), Rule 6020x (Multiple Windows Logon Failures), Account Lockout Rule (Level 9) |
| Severity | Level 10 (highest observed) |

## 3. Timeline

At 20:03:54, the SIEM began logging repeated `Logon Failure - Unknown user or bad password` events on the `administrator` account. Over the following ~50 seconds, multiple failed login attempts were recorded in rapid succession. Wazuh's correlation engine escalated this to a **"Multiple Windows Logon Failures"** alert (Level 10) after detecting the repeated-failure pattern, and Windows subsequently locked the account after repeated invalid attempts.

## 4. Indicators of Compromise (IOCs)

- **Target account:** `administrator`
- **Target host:** `windows11-client` (10.0.2.5)
- **Pattern:** >5 failed logins within ~1 minute

## 5. Analysis / Why This Matters

This pattern is consistent with a brute-force credential-guessing attack. The rapid succession and volume of failures — rather than a single mistyped password — indicates automated attempts rather than genuine user error.

## 6. Response / Recommended Action

- Confirm the account lockout is in effect
- Investigate source of attempts (in this test, self-generated via PowerShell for detection validation)
- Recommend: enforce account lockout policy (already triggered here), enable MFA, monitor for continued attempts from the same source

## 7. Root Cause / Test Note

This was a self-initiated detection test using a local PowerShell script simulating failed login attempts, performed to validate Wazuh's brute-force detection capability. **No actual malicious activity occurred.**

---
*Part of an ongoing home SOC lab — see repo README for the full lab index.*
