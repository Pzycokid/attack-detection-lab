# T1021.001 — Remote Services: Remote Desktop Protocol

| | |
|---|---|
| **Tactic** | Lateral Movement |
| **Technique** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) |
| **Simulation** | Atomic Red Team T1021.001 / lab RDP session |

## What it is

Once attackers have valid credentials, RDP lets them log in to another machine with a full
interactive desktop — quiet, built-in, and often allowed through internal firewalls. Detecting
*who* is RDP-ing *where* is core lateral-movement hunting.

## How to simulate (benign, in lab)

Enable RDP on a second lab VM and connect to it from the first with the `mstsc` client using a lab
account, or run `Invoke-AtomicTest T1021.001`. Keep it inside host-only networking.

## Telemetry it produces

| Log source | Event ID | What to look at |
|---|---|---|
| Security | **4624** | Successful logon — filter **LogonType 10** (RemoteInteractive) |
| Security | 4625 | Failed logon (brute-force / spray signal) |
| Security | 4778 / 4779 | Session reconnected / disconnected |
| Sysmon/Operational | 3 | Network connection to TCP **3389** |

## Detection logic

Base rule: successful logon (**4624**) with **LogonType 10**. See [`detection.yml`](detection.yml).
A single rule for this is noisy by design — the real detection value is **correlation**:
- RDP from a host that normally never initiates RDP
- RDP using a service or admin account outside business hours
- A spike of **4625** failures followed by a **4624** success (successful brute force)

## False positives

Help-desk and sysadmin remote sessions are legitimate RDP. That is why this rule is `level: low`
on its own — it is meant to feed correlation and hunting, not to page an analyst by itself.

## Validate

Make an RDP connection in the lab, open the Security log, find **4624**, and confirm
`LogonType = 10` and the source workstation/IP fields.
