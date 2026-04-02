# Results So Far

These are the lab tests.

---

## Current Live Sentinel Results

The current workspace has real rows in the `HomeLab*` tables.

| Table | Rows | What it shows |
|---|---|---|
| `HomeLabSecurity_CL` | 18 | 10 RDP brute force rows, 6 lateral movement fail rows, 2 lateral movement success rows |
| `HomeLabNetwork_CL` | 200 | Port scan replay from the Ubuntu attacker VM |
| `HomeLabSysmon_CL` | 2 | LibreOffice macro chain and reverse-shell callback |

| Query | Result |
|---|---|
| RDP brute force | 1 row, 10 failed attempts from `192.168.57.101` |
| Lateral movement | 1 row, 16 failed and 2 successful logons on the same IP/user/computer |
| Port scan | 1 row, 200 ports hit from `192.168.57.101` |
| Macro chain | 1 row, `soffice.bin` from LibreOffice |
| Reverse shell | 1 row, `powershell.exe` callback to `192.168.57.1:4444` |

The exact query outputs are in [evidence/live-sentinel-results.md](evidence/live-sentinel-results.md).

## Confirmed Tests

| Date | Test | Command | What showed up | Result |
|---|---|---|---|---|
| Jan 25 2026 | RDP brute force | `hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.57.10 -t 4` | Lots of 4625 failed logons with LogonType 10 | My `rdp-brute-force.kql` rule fired after 10 failed logons and the alert showed up in Sentinel about 3-4 minutes later |
| Feb 3 2026 | Lateral movement sim | `crackmapexec smb 192.168.57.10 -u administrator -p Password123 --shares` | 4624 successful logon and 4776 credential validation | My lateral movement rule fired on the IP + username combo |
| Feb 10 2026 | Port scan | `nmap -sV -O 192.168.57.10` | Burst of blocked connections in pfSense logs | My port scan rule fired and detected 200+ ports hit within 2 minutes |

---

## Live Lab Replay

I replayed the port scan through pfSense after adding a narrow block rule on the LAN side.

| Date | Test | Command | What showed up | Result |
|---|---|---|---|---|
| Mar 29 2026 | pfSense block-rule port scan replay | `nmap -Pn -sT -T4 --max-retries 0 --host-timeout 2m -p 1-200 192.168.57.10` | 401 pfSense filterlog lines and 200 unique destination ports from `192.168.56.101` to `192.168.57.10` | This confirmed the current lab wiring still catches the scan path on the firewall side |

The rule was named `lab-scan-block`, and logging was enabled.

---

## Live Completion Run

These are the runs I would show first.

| Date | Test | Command | What showed up | Result |
|---|---|---|---|---|
| Mar 29 2026 | RDP brute force replay | 10 failed FreeRDP auth-only attempts against `labuser` on `192.168.57.10`, then `Administrator / dees` | Windows Security log showed the attacker source IP `192.168.56.101` and the failed auth events | The brute force pattern is real in the lab |
| Mar 29 2026 | Lateral movement replay | Three failed `Administrator` auth-only attempts, then a successful `Administrator / dees` auth-only run | Windows Security log showed the success after the failures | The same-user failure-then-success pattern is still usable |
| Mar 29 2026 | Port scan replay | `nmap -Pn -n -p 1-200 -T4 --max-retries 0 192.168.57.10` | pfSense `filter.log` showed blocked packets from `192.168.56.101` to `192.168.57.10` | The firewall-side scan proof is still usable |
| Mar 29 2026 | LibreOffice macro replay | `officehelper.bootstrap()` against `AttackLab.Module1.Main` | `macro-ran` was written to `C:\Temp\macro-proof.txt` and Sysmon Event ID 1 showed `soffice.bin` spawning `cmd.exe` | The phishing / macro chain is real in the lab |
| Mar 29 2026 | Reverse-shell style callback | Hidden `powershell.exe` running `C:\Temp\rev_callback.ps1` | Host listener logged `CONNECTED 192.168.57.10:49781` and Sysmon Event ID 3 showed the outbound PowerShell connection to `192.168.57.1:4444` | The callback path is real in the lab |

The short writeup and proof notes are in [evidence/live-completion.md](evidence/live-completion.md).

---

## What I Learned From The Tests

- The brute force rule works
- The lateral movement query still needs tuning
- The port scan query works once pfSense logs flow
- The macro chain works with `soffice.exe` and `soffice.bin`
- The callback is easy to see in Sysmon

---

## Deferred for Later

- `AMA migration`
- `Playbook automation`

Those are still in the repo, but they are cleanup items now instead of blockers for the core lab build.

---

## Archived Live Sentinel Check

The live Sentinel workspace note from Mar 28 2026 is still useful here:

- The RDP brute force query history showed `0 results`
- The table picker search for `SecurityEvent` showed `No tables to display`
- No fresh attack telemetry was in the current workspace range

The full note is in [evidence/current-sentinel-verification.md](evidence/current-sentinel-verification.md). Raw captures stay as context, not proof.

---

## Final Take

Current result set:

- Historical detections from January and February still stand in the repo
- The Mar 29 Windows Security replay gives fresh RDP and logon proof
- The Mar 29 pfSense replay gives fresh firewall proof
- The Mar 29 LibreOffice macro replay gives fresh macro proof
- The Mar 29 reverse-shell callback gives fresh Sysmon network proof

The core lab is complete for this build. The only deferred items are AMA and playbook cleanup.

## Proof Images

The screenshots are in [evidence/screenshots](evidence/screenshots).
