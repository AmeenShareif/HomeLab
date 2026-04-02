# Live Completion Evidence

Date: Mar 29 2026

Live lab run.

## Run details

- RDP brute force replay:
  - `UbuntuAttacker` ran 10 failed FreeRDP auth-only attempts against `labuser` on `192.168.57.10`, then `Administrator / dees` for a clean success.
  - The Windows Security log captured the attacker source IP `192.168.56.101` and the failed and successful auth events.
- Lateral movement replay:
  - Three failed `Administrator` auth-only attempts ran first, then one success.
  - The Windows Security log showed the same-user success after the failures.
- Port scan replay:
  - `nmap -Pn -n -p 1-200 -T4 --max-retries 0 192.168.57.10` ran from `UbuntuAttacker`.
  - pfSense `filter.log` showed the blocked packets from `192.168.56.101` to `192.168.57.10`.
- LibreOffice macro replay:
  - The AttackLab Basic library in LibreOffice called `AttackLab.Module1.Main` through `officehelper.bootstrap()`.
  - The macro wrote `macro-ran` to `C:\Temp\macro-proof.txt`.
  - Sysmon Event ID 1 showed `soffice.bin` spawning `cmd.exe /c echo macro-ran > C:\Temp\macro-proof.txt`.
- Reverse-shell style callback:
  - A hidden `powershell.exe` process on `WindowsServer2019` ran `C:\Temp\rev_callback.ps1`.
  - The guest connected back to the host listener on `192.168.57.1:4444`.
  - The listener log recorded the connection from `192.168.57.10:49781`, and Sysmon Event ID 3 showed the outbound PowerShell connection.

## Macro Proof

The LibreOffice bootstrap helper made the macro run in the lab without guessing at a TCP listener.

```text
BOOTSTRAP_OK
MSPF_OK
SP_OK
SCRIPT_OK
INVOKE_OK (None, (), ())
```

The important Sysmon Event ID 1 lines were:

```text
Image: C:\Windows\System32\cmd.exe
CommandLine: C:\Windows\SYSTEM32\cmd.exe /c echo macro-ran > C:\Temp\macro-proof.txt
ParentImage: C:\Program Files\LibreOffice\program\soffice.bin
ParentCommandLine: "C:\Program Files\LibreOffice\program\soffice.exe" "--nologo" "--nodefault" "--accept=pipe,name=uno6786896129331578;urp;" "-env:OOO_CWD=2C:\\Users\\Administrator"
```

## Reverse-Shell Proof

The listener on the host wrote this after the guest connected:

```text
LISTENING
READY
CONNECTED 192.168.57.10:49781
DATA
```

The matching Sysmon Event ID 3 lines were:

```text
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceIp: 192.168.57.10
DestinationIp: 192.168.57.1
DestinationPort: 4444
```

## Notes

- Completion proof files
- Raw captures stay archived
- Ubuntu through pfSense covers the scan path, and Windows covers Security, Sysmon, macro, and callback proof
