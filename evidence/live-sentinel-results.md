# Live Sentinel Results

Date: Mar 31 2026

Current Sentinel replay.

## Table Counts

| Table | Rows | Notes |
|---|---|---|
| `HomeLabSecurity_CL` | 18 | RDP brute force and lateral movement replay rows |
| `HomeLabNetwork_CL` | 200 | pfSense port-scan replay rows |
| `HomeLabSysmon_CL` | 2 | LibreOffice macro and reverse-shell callback rows |

## Security Breakdown

| Attack type | Rows |
|---|---|
| `rdp_bruteforce` | 10 |
| `lateral_movement_fail` | 6 |
| `lateral_movement_success` | 2 |

## RDP Brute Force Query

Query:

```kql
HomeLabSecurity_CL
| where EventID_d == 4625 and LogonType_d == 10
| summarize FailedAttempts=count(), FirstAttempt=min(TimeGenerated), LastAttempt=max(TimeGenerated), Accounts=make_set(TargetUserName_s) by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
| project TimeGenerated, IPAddress, FailedAttempts, Accounts, FirstAttempt, LastAttempt, TimespanMinutes=datetime_diff('minute', LastAttempt, FirstAttempt)
```

Result:

| IPAddress | FailedAttempts | Accounts | FirstAttempt | LastAttempt | TimespanMinutes |
|---|---|---|---|---|---|
| `192.168.57.101` | `10` | `["Administrator"]` | `2026-03-31T05:07:02.3334553Z` | `2026-03-31T05:07:02.3334553Z` | `0` |

## Lateral Movement Correlation

Count-based query here because the replay rows came in with the same ingest-time style timestamps.

Query:

```kql
HomeLabSecurity_CL
| where EventID_d in (4625, 4624) and LogonType_d in (3, 10)
| summarize FailCount=countif(EventID_d == 4625), SuccessCount=countif(EventID_d == 4624), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by IPAddress, TargetUserName_s, Computer
| where FailCount >= 3 and SuccessCount >= 1
| project TimeGenerated=LastSeen, IPAddress, TargetUserName_s, Computer, FailCount, SuccessCount, FirstSeen, LastSeen, MinutesBetween=datetime_diff('minute', LastSeen, FirstSeen)
```

Result:

| IPAddress | TargetUserName_s | Computer | FailCount | SuccessCount | FirstSeen | LastSeen | MinutesBetween |
|---|---|---|---|---|---|---|---|
| `192.168.57.101` | `Administrator` | `WindowsServer2019` | `16` | `2` | `2026-03-31T05:07:02.3334553Z` | `2026-03-31T05:17:13.2445927Z` | `10` |

## Port Scan Query

Query:

```kql
HomeLabNetwork_CL
| where DeviceVendor_s == "pfSense" and DeviceAction_s == "block"
| summarize PortsScanned=dcount(DestinationPort_d), PortList=make_set(DestinationPort_d), ScanStart=min(TimeGenerated), ScanEnd=max(TimeGenerated), PacketCount=count() by SourceIP, DestinationIP_s, bin(TimeGenerated, 2m)
| where PortsScanned >= 20
| extend DurationSeconds=datetime_diff('second', ScanEnd, ScanStart)
| extend PortsPerSecond=iif(DurationSeconds <= 0, real(null), round(toreal(PortsScanned) / todouble(DurationSeconds), 2))
```

Result:

| SourceIP | DestinationIP_s | PortsScanned | PacketCount | DurationSeconds | PortsPerSecond |
|---|---|---|---|---|---|
| `192.168.57.101` | `192.168.57.10` | `200` | `200` | `0` | `null` |

## Macro Chain Query

Query:

```kql
HomeLabSysmon_CL
| where EventID_d == 1 and Image_s has "soffice.bin" and CommandLine_s has "macro.docm"
| project TimeGenerated, Computer, User_s, Image_s, ParentImage_s, CommandLine_s, AttackType_s
```

Result:

| Image_s | ParentImage_s | CommandLine_s | User_s | AttackType_s |
|---|---|---|---|---|
| `C:\Program Files\LibreOffice\program\soffice.bin` | `C:\Windows\explorer.exe` | `soffice.bin --headless macro.docm` | `ameen` | `macro_chain` |

## Reverse Shell Query

Query:

```kql
HomeLabSysmon_CL
| where EventID_d == 3 and DestinationPort_d == 4444
| project TimeGenerated, Computer, User_s, Image_s, DestinationIp_s, DestinationPort_d, Protocol_s, AttackType_s
```

Result:

| Image_s | DestinationIp_s | DestinationPort_d | Protocol_s | AttackType_s |
|---|---|---|---|---|
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `192.168.57.1` | `4444` | `tcp` | `reverse_shell` |
