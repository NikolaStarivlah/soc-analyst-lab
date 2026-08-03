# Day 1 — Virtual Lab Environment Setup

**Status:** Complete
**Goal:** Stand up the base VMs and networking for the SOC lab (Elastic, Suricata, Sysmon, Wazuh, AD to follow in later phases).

## Environment

| VM | OS | RAM / CPU / Disk | NAT IP | Host-Only IP |
|---|---|---|---|---|
| Ubuntu-SIEM | Ubuntu Server 24.04.4 LTS | 8 GB / 2 vCPU / 80 GB | 10.0.2.15 | 192.168.56.112 |
| windows10victim | Windows 10 Pro (64-bit) | 4 GB / 2 vCPU / 80 GB | 10.0.2.15 | 192.168.56.114 |
| kali-lab | Kali Linux 2026.2 (Xfce) | 2 GB / 2 vCPU / 50 GB | 10.0.2.15 | 192.168.56.115 |

> Windows 10 **Pro** was used instead of Home — Home can't join an AD domain, which is required in Phase 10.

## Network Design

- **Host-only subnet:** `192.168.56.0/24` — VM-to-VM lab traffic
- **NAT adapter:** internet access per VM (all show `10.0.2.15` — expected, NAT is isolated per-VM)
- Confirmed bidirectional ping between all three VMs over host-only
- Confirmed NAT internet access on all three VMs

## Issues & Fixes

**1. Windows blocked inbound ICMP (ping) by default**
```powershell
Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True
```

**2. Kali's installer only configures NetworkManager for the "primary" interface (eth0/NAT)** — the host-only adapter (eth1) came up unconfigured.
```bash
sudo nmcli device connect eth1
```
Watch out: if only one generic connection profile exists, connecting a second interface can silently steal the profile from the first. Fix by giving each interface its own named profile:
```bash
sudo nmcli connection add type ethernet ifname eth0 con-name "eth0-nat"
sudo nmcli connection up "eth0-nat"
```

**3. `ssh.service` shows "inactive (dead)" on Ubuntu 24.04 at idle** — this is normal socket activation, not a failure. Check the socket instead:
```bash
sudo systemctl status ssh.socket   # should show "active (listening)"
```

## Snapshots Taken

- `Phase1-Clean-Ubuntu-Networking-Working`
- `Phase1-Clean-Windows-Networking-Working`
- `Phase1-Clean-Kali-Networking-Working`

---
**Next:** Phase 2 — Deploy Elastic SIEM + Suricata IDS on Ubuntu-SIEM
