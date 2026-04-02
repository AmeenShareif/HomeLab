# Project Status

Last updated: Mar 29 2026

Current status for the lab.

---

## Current State

| Status | What I finished or hit | Notes |
|---|---|---|
| Done | pfSense reinstall and subnet split | pfSense is installed on UFS, LAN is `192.168.56.2/24`, and OPT1 is `192.168.57.2/24` |
| Done | Ubuntu route cleanup | UbuntuAttacker routes through pfSense instead of the VirtualBox NAT gateway |
| Done | Windows Server boot and guest setup | WindowsServer2019 now reaches the desktop, has the static IP, and has Sysmon and RDP enabled |
| Done | Sysmon download | Sysmon is downloaded and unpacked under `tools/Sysmon` |
| Done | Live RDP replay | 10 failed RDP auth-only attempts and a successful admin auth from Ubuntu attacker |
| Done | Live lateral-movement replay | Three failed Administrator auth-only attempts followed by a success |
| Done | Live port-scan replay | pfSense logged 401 blocked packets and 200 unique destination ports from the Ubuntu attacker VM |
| Done | Current live Sentinel replay | `HomeLabSecurity_CL`, `HomeLabNetwork_CL`, and `HomeLabSysmon_CL` all return real rows now |
| Done | Live LibreOffice macro replay | LibreOffice AttackLab macro wrote `macro-ran` and Sysmon showed `soffice.bin` spawning `cmd.exe` |
| Done | Live reverse-shell style callback | Hidden PowerShell process connected back to the host listener and Sysmon logged the outbound connection |
| Done | Base lab setup | pfSense, Ubuntu attacker VM, and Windows Server are wired up in VirtualBox |
| Done | Core detections | RDP brute force, lateral movement, port scan, and IOC hunting |
| Done | Basic writeups | Setup guide, hunting log, and attack-chain walkthrough |
| Deferred | AMA migration | Replace the Windows collector setup later when the guest is usable |
| Deferred | Playbook automation | Basic Sentinel response flow, not wired up yet |

---

## Recent Updates

- Rebuilt pfSense and split the lab into `192.168.56.0/24` and `192.168.57.0/24`
- Moved UbuntuAttacker to pfSense
- Downloaded Sysmon
- Finished the Windows replay with RDP, lateral movement, and Security logs
- Replayed the port scan through pfSense
- Added the live Sentinel replay note
- Added the port-scan replay note
- Kept the docs pointed at the proof files
- Finished the macro chain and reverse-shell callback
- Tuned `phishing-macro-chain.kql`
- Added `attack-chain-walkthrough.md`
- Left AMA migration and playbook automation deferred

---

## Final Read

- No active WIP items remain for the core lab
- The live proof is the Windows Security replay, the pfSense replay, the macro replay, the callback, and the current Sentinel replay
- The older Jan and Feb detections stay in `results.md`
- The remaining items are cleanup work
