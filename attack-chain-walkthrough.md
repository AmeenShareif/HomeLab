# Attack Chain Walkthrough

End-to-end macro test from the lab.

---

## Goal

- Start with a macro-enabled LibreOffice document
- Run the macro on the Windows VM
- Check Sysmon and Windows logs
- See which detection rules fire

---

## Chain

### 1. Macro-enabled document

I used the LibreOffice AttackLab Basic library and called `AttackLab.Module1.Main`.

### 2. Macro starts

The macro wrote `macro-ran` to `C:\Temp\macro-proof.txt`.

### 3. Script or shell activity

The macro spawned `cmd.exe`.

### 4. Outbound callback

I then launched a hidden PowerShell callback that connected back to my host listener on `192.168.57.1:4444`.

### 5. Sentinel alert

Sentinel had enough pieces to show the whole chain.

---

## What I would check in the logs

- ParentImage and Image
- CommandLine
- User
- Destination IP and destination port
- Whether the process started from LibreOffice or a script host
- Whether anything else happened right after it

---

## Notes

- Reference chain for the repo
- Replayed in the current build
