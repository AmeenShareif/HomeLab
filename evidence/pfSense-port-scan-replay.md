# pfSense Port Scan Replay

Date: Mar 29 2026

The port-scan path through pfSense was replayed after a tight LAN block rule was added.

## Rule Used

- Name: `lab-scan-block`
- Interface: `LAN`
- Source: `192.168.56.101`
- Destination: `192.168.57.10`
- Action: `block`
- Logging: on

## Attack Run

```bash
nmap -Pn -sT -T4 --max-retries 0 --host-timeout 2m -p 1-200 192.168.57.10
```

## What I Saw

- `401` blocked pfSense filterlog lines in the relay log
- `200` unique destination ports in the replay
- The scan stayed inside the host-only lab network

## Why This Matters

This gives fresh proof that the port-scan path is still working on the current lab build.
The firewall is catching the scan, the relay is receiving the logs, and the attack stays isolated from the outside network.
