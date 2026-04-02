# Lab Setup Guide

How I built the lab.

---

## Prerequisites

- A machine with at least 16GB RAM
- VirtualBox 7.0
- Azure free account (for Sentinel)
- Time for setup and reboot loops

---

## Step 1: VirtualBox Network Setup

Before creating any VMs, set up two host-only networks in VirtualBox.

VirtualBox > Tools > Network Manager > Create two host-only adapters:

| Adapter | IP Range | DHCP |
|---|---|---|
| vboxnet0 | 192.168.56.0/24 | Disabled |
| vboxnet1 | 192.168.57.0/24 | Disabled |

Disable DHCP on both.

---

## Step 2: pfSense

**Download:** https://www.pfsense.org/download/ (AMD64, ISO)

**VM Settings:**
- 1 CPU, 512MB RAM (pfSense is lightweight)
- 3 network adapters:
  - Adapter 1: NAT (WAN — for internet access)
  - Adapter 2: Host-only vboxnet0 (LAN — Ubuntu attacker side)
  - Adapter 3: Host-only vboxnet1 (OPT1 — Windows side)

**Install:**
- Boot ISO, go through installer defaults
- Assign interfaces when prompted: WAN = em0, LAN = em1, OPT1 = em2
- Set LAN IP to 192.168.56.2/24
- Set OPT1 IP to 192.168.57.2/24

**After install — web UI (from the Ubuntu attacker VM or any machine on 192.168.56.x):**
- Navigate to https://192.168.56.2 — default creds are admin/pfsense
- Firewall > Rules > LAN: keep the allow rule for traffic from 192.168.56.0/24 to 192.168.57.0/24
- Enable logging on block rules so denies show up in syslog

**Syslog forwarding:**
- Status > System Logs > Settings
- Enable remote logging
- Set remote syslog server to your log forwarder IP (I used a small Ubuntu VM running rsyslog)
- Check "Firewall Events"

---

## Step 3: Ubuntu attacker VM

**Download:** Any Ubuntu Desktop ISO works here. I used Ubuntu because that is what I had on hand, and it was enough for hydra, nmap, and the rest of the lab tools.

**VM Settings:**
- 2 CPU, 4GB RAM
- Network: Host-only vboxnet0

**Install the tools I used:**
```bash
sudo apt update
sudo apt install -y hydra nmap
```

Install `crackmapexec` if needed.

**Static IP setup:**
```bash
sudo nano /etc/network/interfaces
```
```
auto eth0
iface eth0 inet static
    address 192.168.56.101
    netmask 255.255.255.0
    gateway 192.168.56.2
```
```bash
sudo systemctl restart networking
```

**Verify routing to Windows subnet:**
```bash
ping 192.168.57.10
# should work once Windows VM is up and pfSense rules are set
```

---

## Step 4: Windows Server 2019

**Download:** https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019 (180 day eval, free)

**VM Settings:**
- 2 CPU, 4GB RAM
- Network: Host-only vboxnet1

**Static IP:**
- Control Panel > Network > Ethernet > IPv4
- IP: 192.168.57.10
- Subnet: 255.255.255.0
- Gateway: 192.168.57.2

**Unattended login found in VirtualBox:**
- Username: `seed`
- Password: `dees`
- Local admin password: `dees`

**Enable RDP:**
- Server Manager > Local Server > Remote Desktop > Enable
- Allow through Windows Firewall when prompted

**Enable audit policies (important for log generation):**
```
Run > secpol.msc > Local Policies > Audit Policy
```
Enable Success + Failure for:
- Audit logon events
- Audit account logon events
- Audit object access

Or just run this in an elevated PowerShell:
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
```

---

## Step 5: Sysmon

Download from Microsoft Sysinternals and install with the SwiftOnSecurity config:

```powershell
# Download sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip

# Download config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Verify it's running:
```powershell
Get-Service sysmon64
```

---

## Step 6: Microsoft Sentinel

1. Go to portal.azure.com — create a free account if you don't have one
2. Create a **Log Analytics Workspace** (this is where logs actually go)
   - Resource group: create new, call it something like `homelab-rg`
   - Region: pick whatever's closest to you
3. Search for **Microsoft Sentinel** > Add > select your workspace
4. Go to **Data Connectors** > search "Windows Security Events" > install via AMA or MMA

**Install MMA agent on Windows Server:**
- In Sentinel: Settings > Workspace Settings > Agents > Windows Servers > Download Windows Agent (64-bit)
- Install on the Windows VM
- During install, enter your Workspace ID and Primary Key (found in the same Agents page)
- Give it 20-30 minutes to show as connected — it'll say disconnected at first even if it's working, don't panic

**Verify logs are flowing:**
In Sentinel > Logs, run:
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| take 10
```
If you get results, the workspace is receiving logs.

---

## Step 7: pfSense Log Ingestion

pfSense does not send logs in CEF format natively, so use a relay.

**Option I used: Ubuntu VM as syslog relay**

```bash
# Install rsyslog
sudo apt install rsyslog -y

# Create a config to receive from pfSense and forward to Azure
sudo nano /etc/rsyslog.d/50-pfsense.conf
```

```
# Receive UDP syslog from pfSense
module(load="imudp")
input(type="imudp" port="514")

# Forward to Log Analytics (after installing OMS agent)
*.* @127.0.0.1:25224
```

Then install the OMS (Log Analytics) agent on the Ubuntu VM and connect it to the same workspace. pfSense logs will come in under the `Syslog` table.

Custom parser to normalize the fields is in `pfsense-parser.kql`. I also keep a local Python parser in `pfsense_parser.py` when I want to inspect logs outside Sentinel.

---

## Troubleshooting

**MMA agent shows disconnected:**
Wait longer. Also check that port 443 outbound is open on pfSense for the Windows VM.

**Logs not showing in Sentinel:**
Check the workspace ID and key are correct in the agent config. On Windows: Control Panel > Microsoft Monitoring Agent > Azure Log Analytics tab.

**pfSense syslog not arriving on relay:**
Check pfSense firewall rules aren't blocking UDP 514 outbound on the LAN interface. Also make sure rsyslog is actually listening: `sudo netstat -ulnp | grep 514`

**VMs can't ping each other:**
Usually a pfSense firewall rule issue. Check Firewall > Rules on the relevant interface. Also make sure the OPT1 interface has "Block private networks" unchecked.
