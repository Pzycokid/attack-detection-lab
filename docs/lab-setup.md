# Lab Setup

A minimal, free lab to reproduce every detection in this repo. Everything runs locally on
host-only networking, so nothing is exposed to the internet or to any system you don't own.

## 1. Virtual machine

- **Hypervisor:** VirtualBox or VMware Workstation Player (both free).
- **Guest:** Windows 10 or 11 Evaluation VM (Microsoft publishes free time-limited images).
- **Networking:** set the adapter to **Host-only**. This is what keeps the lab isolated.
- Take a **snapshot** of the clean VM so you can roll back after each test.

## 2. Turn on the telemetry

Most attacker behaviour is invisible until you enable the right logging.

### Sysmon
Sysmon gives you high-quality process, network, and registry events.

1. Download Sysmon from Microsoft Sysinternals.
2. Use a well-known config as a baseline (for example, the SwiftOnSecurity `sysmonconfig.xml`).
3. Install: `sysmon.exe -accepteula -i sysmonconfig.xml`
4. Events appear under **Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**.

### PowerShell logging
Enable via Group Policy (`gpedit.msc`) →
*Administrative Templates → Windows Components → Windows PowerShell*:
- **Turn on Module Logging**
- **Turn on PowerShell Script Block Logging** → produces **Event ID 4104**

### Audit policy
In `gpedit.msc` → *Security Settings → Advanced Audit Policy Configuration*, enable:
- **Logon/Logoff → Audit Logon** (for RDP logon events 4624/4625)
- **Object Access → Audit Other Object Access Events** (for scheduled task 4698)

## 3. Install the simulation tool

Use the published **Atomic Red Team** project — it ships small, benign, well-documented tests
mapped to ATT&CK IDs. In an elevated PowerShell in the lab VM:

```powershell
# Reference: https://github.com/redcanaryco/invoke-atomicredteam/wiki
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Each technique folder in this repo names the exact atomic test to run.

## 4. (Optional) Central SIEM

To practise the full analyst workflow, ship logs to a SIEM:
- **Wazuh** (free, open source) — install the agent in the VM, point it at a Wazuh manager.
- **Splunk Free** or **Elastic** — use Winlogbeat to forward Windows + Sysmon logs.

You can complete every detection in this repo just by reading the Windows Event Viewer, but
forwarding to a SIEM lets you test the Sigma rules as real searches.

## 5. Workflow per technique

1. Snapshot the clean VM.
2. Run the named atomic test.
3. Open Event Viewer / your SIEM and find the events listed in the technique writeup.
4. Confirm the Sigma rule logic matches what you see.
5. Note any false-positive sources.
6. Roll back to the snapshot.
