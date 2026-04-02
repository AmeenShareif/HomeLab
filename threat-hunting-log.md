# Threat Hunting Log

Running notes from each session.

---

## Session 1
**Date:** Jan 14 2026  
**Goal:** Get baseline logs flowing into Sentinel

**Run:**
- Installed MMA agent on Windows Server, connected to Log Analytics workspace
- Verified SecurityEvent table was populating in Sentinel
- Ran a basic KQL query to confirm 4624/4625 events were coming through

**Issue:**
- Agent kept showing as disconnected in the portal even though logs were flowing. Turns out it just takes like 20-30 min to show healthy after install. Wasted an hour on that.
- Had to open port 443 outbound on pfSense for the agent to reach Azure endpoints

**Result:** Baseline setup only.

**Next:** Set up Sysmon and compare it with Windows Security logs

---

## Session 2
**Date:** Jan 19 2026  
**Goal:** Install Sysmon and compare visibility

**Run:**
- Deployed Sysmon with SwiftOnSecurity config
- Waited ~30 min for logs to flow
- Compared process creation events (Sysmon Event ID 1) vs what Windows Security logs alone gave me

**Result:**
- Sysmon gives way more detail. Parent process, command line args, hashes — stuff that Windows Security logs just don't have
- Without Sysmon you can see that *something* ran but not really *what* it did
- Event ID 3 (network connection) from Sysmon is really useful — can see outbound connections per process

**Note:**
- SwiftOnSecurity config excludes a lot of noise by default (system processes etc). Good starting point but I'd want to tune it more for a real environment
- Sysmon log size can get big fast if you're not filtering. Keep an eye on disk

---

## Session 3
**Date:** Jan 25 2026  
**Goal:** Simulate RDP brute force

**Attack:**
```
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.57.10 -t 4
```

**Logs:**
- Tons of 4625 events (failed logon, LogonType 10)
- Source IP was consistent (Ubuntu attacker VM 192.168.56.101)
- TargetUserName was "administrator" across all attempts

**Result:**
- Default Microsoft "Brute force attack against Azure Portal" rule didn't fire — that's Azure-specific, not on-prem
- Wrote custom KQL rule (`rdp-brute-force.kql`) — fired correctly after hitting the 10-attempt threshold
- Alert showed up in Sentinel incidents tab about 3-4 minutes after the attack started

**Next:**
- The rule fires per 5-min bin. If an attacker goes slow (1 attempt every 30 sec) it won't trigger. Need to think about how to handle low-and-slow brute force
- Should add logic to check if a success followed the failures

---

## Session 4
**Date:** Feb 3 2026  
**Goal:** Simulate lateral movement

**Attack:**
```
crackmapexec smb 192.168.57.10 -u administrator -p Password123 --shares
```
(used a password I already knew worked — simulating post-credential-theft movement)

**Logs:**
- Event 4624 LogonType 3 (network logon) from the Ubuntu attacker VM IP
- Event 4776 (NTLM credential validation)
- Sysmon Event 3 on the Windows box showing inbound SMB connection

**Result:**
- Lateral movement rule fired. Matched on the IP + username combo with prior failures from earlier testing
- Had to tune it — was getting false positives from my own admin activity during lab setup. Added a filter to exclude my known admin IP

**Note:**
- In a real environment you'd want to baseline what normal lateral movement looks like (admins doing legit stuff) before deploying this rule
- Pass-the-hash would look similar but you'd see NTLMv2 in the 4776 events instead of cleartext validation

---

## Session 5
**Date:** Feb 10 2026  
**Goal:** Nmap scan detection via pfSense logs

**Attack:**
```
nmap -sV -O 192.168.57.10
```

**Logs:**
- Burst of blocked connection attempts across ports 1-1024 and common high ports
- Source IP: 192.168.56.101 from the Ubuntu attacker VM

**Result:**
- Took a while to get pfSense logs into Sentinel correctly. Had to configure syslog on pfSense to forward to a syslog receiver (used a Linux VM), then forward to Log Analytics via the agent
- Port scan rule fired once I had the logs flowing — detected 200+ ports hit within 2 minutes
- PortsPerSecond metric came out to ~18/sec which is consistent with a default nmap scan speed

**Issue:**
- pfSense log format isn't CEF by default so CommonSecurityLog table didn't work out of the box. Had to write a basic parser — will add it to the repo
- OS detection (-O flag) generated ICMP traffic that showed up separately from the port scan traffic

---

## Next Ideas

- Phishing simulation — set up a fake email and see if I can track the full chain (email → attachment → execution) in Sentinel
- Sentinel playbooks / Logic Apps for automated response
- Velociraptor for memory forensics on the Windows box
- Try to detect a reverse shell and see what artifacts it leaves

---

## Session 6
**Date:** Mar 28 2026
**Goal:** Add a starting reverse-shell detection query

**Run:**
- Wrote a Sysmon Event ID 3 query that looks for shell-like processes making outbound connections
- Kept it simple on purpose so I can tune it later instead of overengineering it now

**Note:**
- This will probably need trimming once I test it against real lab traffic
- It should pair well with the phishing / macro chain query from the last update

**Next:**
- Run it in the lab with a listener and see what actually shows up in Sysmon

---

## Session 7
**Date:** Mar 28 2026
**Goal:** Write a simple attack chain walkthrough

**Run:**
- Wrote a short markdown doc that connects the phishing, script, and callback pieces together
- Kept it short so it still feels like my lab notes and not a formal report

**Note:**
- This should make the repo easier to understand when I come back to it later
- It also gives me a cleaner story for demoing the lab

**Next:**
- Test the chain in the lab and update the detection queries if needed

---

## Session 8
**Date:** Mar 28 2026  
**Goal:** Make the work in progress easier to see

**Run:**
- Added a simple status page for the active lab work
- Added a short progress table to the README so the repo shows what is done and what is still moving

**Note:**
- This makes the project easier to scan when I come back to it later
- It also makes the repo look more like an active lab instead of a finished one

**Next:**
- Keep updating the status page as I test the phishing and reverse shell pieces

---

## Session 9
**Date:** Mar 28 2026  
**Goal:** Pull the real test results into one place

**Run:**
- Wrote a separate results page with the attacks I actually ran and what fired
- Added a short results block to the README so the confirmed tests are easier to find

**Note:**
- This is better than just saying the lab is a work in progress
- It shows the actual alerts and detections that already worked

**Next:**
- Add more exported query output once I test the remaining queries

---

## Session 10
**Date:** Mar 28 2026
**Goal:** Check the live Sentinel workspace

**Run:**
- Opened the `cisco` workspace in Sentinel Logs through Comet
- Checked the RDP brute force query history
- Searched for `SecurityEvent` in the table picker
- Wrote down the live check in a short note and kept the raw captures archived separately

**Result:**
- The RDP brute force query history showed `0 results` on the checked runs
- The table picker said `No tables to display` when I searched for `SecurityEvent`
- The live workspace is not showing the log data I would need to reproduce the attacks again right now

**Note:**
- This does not erase the older Jan/Feb lab notes, but it does mean the current live workspace is stale
- I need the lab data flow back before I can claim fresh attack telemetry from this session

**Next:**
- Get new telemetry into Sentinel and rerun the detections for real

---

## Session 11
**Date:** Mar 28 2026
**Goal:** Fix the lab network

**Run:**
- Reinstalled pfSense after the old disk boot failed
- Set the pfSense LAN to `192.168.56.2/24`
- Added `em2` as `OPT1` and set it to `192.168.57.2/24`
- Moved UbuntuAttacker to route through pfSense instead of the VirtualBox NAT gateway
- Switched WindowsServer2019 onto the `VirtualBox Host-Only Ethernet Adapter #2` network
- Downloaded and unpacked Sysmon on the host so it is ready for the Windows VM
- Checked the Windows unattended file and found the auto-logon and admin password are both `seed / dees`

**Result:**
- The two host-only subnets are finally separated the way the lab needs
- UbuntuAttacker can reach both pfSense sides now
- WindowsServer2019 is still finishing setup, so the static IP and Sysmon install have to wait

**Note:**
- This was the biggest infrastructure fix in the lab so far
- Once Windows finishes booting, I should be able to finish the host config much faster because the login info is already known

**Next:**
- Wait for WindowsServer2019 to finish setup
- Put the Windows VM on `192.168.57.10/24` with gateway `192.168.57.2`
- Install Sysmon and start generating attack data for Sentinel

---

## Session 12
**Date:** Mar 29 2026
**Goal:** Reproduce the current port-scan path

**Run:**
- Logged into pfSense again and added a tight LAN block rule named `lab-scan-block`
- Set the rule to block traffic from `192.168.56.101` to `192.168.57.10`
- Turned logging on for the rule so the relay would record every blocked packet
- Replayed the scan from UbuntuAttacker with `nmap -Pn -sT -T4 --max-retries 0 --host-timeout 2m -p 1-200 192.168.57.10`
- Counted the relay output and saw 401 blocked filterlog lines and 200 unique destination ports

**Result:**
- The pfSense relay is still working
- The block rule gives me clean port-scan evidence without touching anything outside the lab
- The current Windows guest is still stuck in setup, so I still need to come back for the Windows logon based detections

**Note:**
- This is the best live proof so far that the firewall-side path is wired correctly
- The Windows VM still needs to finish booting before the brute force and lateral movement runs can be repeated

**Next:**
- Keep waiting on WindowsServer2019
- Use the `seed / dees` login once it reaches the desktop
- Install Sysmon and finish the Windows-side tests

---

## Session 13
**Date:** Mar 29 2026
**Goal:** Close out the project around the evidence collected

**Run:**
- Trimmed the docs so they point at the files that actually prove something
- Marked the Windows guest boot as blocked instead of pretending it was finished
- Kept the pfSense replay, the live Sentinel note, and the older Jan/Feb detections as the finished evidence set

**Result:**
- The project is only partially complete for the current scope
- The strongest proof is still the relay log replay with 401 blocked packets and 200 unique destination ports
- There is no working Windows guest in this build, so the Windows-side retest is not being claimed as finished

**Note:**
- This makes the repo honest about what is done and what was blocked
- It also keeps the final story short enough that I can explain it without making it sound bigger than it is

**Next:**
- None for now

---

## Session 14
**Date:** Mar 29 2026
**Goal:** Close out the remaining follow-up items

**Run:**
- Moved the phishing / macro test, reverse shell test, AMA migration, and playbook automation items into deferred status
- Updated the main status pages so they no longer read like active WIP tasks

**Result:**
- Those follow-ups still depend on a usable Windows guest or separate Azure-side setup
- The lab build is fully documented, but the Windows-side retest is still blocked

**Note:**
- This keeps the repo honest about what is finished and what is still waiting
- It also makes the remaining work easier to pick back up later without pretending it was done

**Next:**
- Revisit the deferred items if the Windows guest starts booting normally again

---

## Session 15
**Date:** Mar 29 2026
**Goal:** Finish the current lab replay with real attack data

**Run:**
- Used FreeRDP from UbuntuAttacker with `xvfb-run` so I could do headless auth-only tests
- Ran 10 failed RDP auth-only attempts against a fake `labuser` account on `192.168.57.10`
- Ran a successful `Administrator / dees` auth-only login after the failures
- Ran three failed `Administrator` auth-only attempts and then another success
- Switched pfSense back to the block rule and replayed the port scan with `nmap -Pn -n -p 1-200 -T4 --max-retries 0 192.168.57.10`
- Captured the Windows Security log and the pfSense filter log notes that show the source IP and the blocked packets

**Result:**
- The Windows guest is usable now, so the lab is no longer stuck on the first boot screen
- The RDP and lateral logon patterns are visible in the Windows Security log
- The port scan path is visible in pfSense filter.log with 200 filtered ports

**Note:**
- The earlier Sentinel empty-workspace note is still useful as history, but it is not the main proof anymore
- The completion proof is the live Windows Security replay plus the pfSense filter replay

**Next:**
- Turn the log notes into the final repo proof set
- Leave the extra phishing / reverse shell / AMA / playbook items deferred

---

## Session 16
**Date:** Mar 29 2026
**Goal:** Finish the phishing / macro and reverse-shell proof

**Run:**
- Used `officehelper.bootstrap()` to start LibreOffice in the guest and invoke `AttackLab.Module1.Main`
- Wrote `macro-ran` to `C:\Temp\macro-proof.txt`
- Checked Sysmon Event ID 1 and saw `soffice.bin` spawn `cmd.exe /c echo macro-ran > C:\Temp\macro-proof.txt`
- Launched a hidden `powershell.exe` process that ran `C:\Temp\rev_callback.ps1`
- Had the guest connect back to my host listener on `192.168.57.1:4444`
- Checked Sysmon Event ID 3 and saw the outbound PowerShell connection from `192.168.57.10` to `192.168.57.1:4444`

**Result:**
- The LibreOffice macro chain works in the lab build
- The reverse-shell style callback works once the correct host-only IP is used
- The proof is stronger now because it includes both the file write and the Sysmon process/network events

**Note:**
- The macro query stays pointed at LibreOffice because that is what was used in the lab
- This is the cleanest proof for the phishing / macro and callback part of the project

**Next:**
- Only the AMA migration and playbook cleanup items are left

---

## Session 17
**Date:** Mar 31 2026
**Goal:** Pull real current Sentinel results from the replay tables

**Run:**
- Queried `HomeLabSecurity_CL`, `HomeLabNetwork_CL`, and `HomeLabSysmon_CL` in the live workspace
- Confirmed the workspace had 18 Security rows, 200 network rows, and 2 Sysmon rows
- Ran the RDP brute force query and got a real row back with 10 failed attempts from `192.168.57.101`
- Ran a lateral movement correlation query and got a real row back showing 16 failures and 2 successes on the same IP, user, and computer
- Ran the port scan query and got a real row back with 200 blocked destination ports
- Ran the macro chain query and reverse shell query and got one real row for each

**Result:**
- The current Sentinel proof is now backed by actual query output, not just the old `0 results` note
- The custom replay tables make the lab easier to prove because the rows are already in the workspace

**Next:**
- Keep the repo wording simple and point the main proof links at the live Sentinel results
