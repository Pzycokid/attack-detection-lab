# T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

| | |
|---|---|
| **Tactic** | Persistence |
| **Technique** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| **Simulation** | Atomic Red Team T1547.001 |

## What it is

The `Run` and `RunOnce` registry keys list programs Windows launches automatically when a user
logs on. Adding an entry here is one of the oldest and most common persistence tricks, because it
survives reboots and needs no special privileges for the per-user (HKCU) keys.

## How to simulate (benign, in lab)

```powershell
Invoke-AtomicTest T1547.001
```

## Telemetry it produces

| Log source | Event ID | What to look at |
|---|---|---|
| Sysmon/Operational | **13** | Registry value set — `TargetObject` + `Details` |
| Security | 4657 | Registry value modified (needs registry auditing enabled) |

Sysmon **Event ID 13** is the reliable source here: it fires whenever a value is written and tells
you the exact key and the data written.

## Detection logic

Alert on writes to the autostart keys — `...\CurrentVersion\Run`, `...\RunOnce`, and the
`User Shell Folders` startup locations. See [`detection.yml`](detection.yml). Enrich by checking
the value's data: an entry pointing at a binary in `%TEMP%`, `%APPDATA%`, or `Public` is a strong
signal.

## False positives

Plenty of legitimate apps register themselves to start at logon. Build a baseline of normal Run-key
entries for your environment and alert on deviations, especially entries pointing at user-writable
paths or script interpreters.

## Validate

Run the atomic, open Sysmon/Operational, filter for Event ID 13, and confirm the `TargetObject`
is one of the Run keys and `Details` shows the planted command.
