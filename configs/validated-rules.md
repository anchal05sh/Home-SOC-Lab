# Validated Detection Rules

Running index of Wazuh rules confirmed working, and which lab proved it.

## Authentication / Brute-Force

| Rule ID | Level | Description | Validated in |
|---|---|---|---|
| 6012x | — | Logon Failure | [Lab 01](../reports/lab01-brute-force-detection.md) |
| 6020x | 10 | Multiple Windows Logon Failures | [Lab 01](../reports/lab01-brute-force-detection.md) |
| Account Lockout Rule | 9 | Account locked after repeated invalid attempts | [Lab 01](../reports/lab01-brute-force-detection.md) |

## File Integrity Monitoring (FIM)

| Rule ID | Level | Description | Validated in |
|---|---|---|---|
| 554 | 5 | File added to the system | [Lab 02](../reports/lab02-eicar-detection-test.md) |
