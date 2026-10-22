# T1053.005 — Scheduled Task/Job: Scheduled Task

| | |
|---|---|
| **Tactic** | Execution / Persistence |
| **Technique** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| **Simulation** | Atomic Red Team T1053.005 |

## What it is

A scheduled task tells Windows to run a program at a time or trigger of the attacker's choosing —
at logon, at boot, or on a schedule. It is a durable way to keep code running after a reboot, and
it blends in because scheduled tasks are everywhere on a normal machine.

## How to simulate (benign, in lab)

```powershell
Invoke-AtomicTest T1053.005
```

The atomics create a harmless scheduled task and then clean it up.

## Telemetry it produces

| Log source | Event ID | What to look at |
|---|---|---|
| Security | **4698** | A scheduled task was created (full task XML in the event) |
| Security | 4702 | A scheduled task was updated |
| Microsoft-Windows-TaskScheduler/Operational | 106 | Task registered |
| Sysmon/Operational | 1 | `schtasks.exe` or `powershell.exe` process + command line |

## Detection logic

Watch process creation for `schtasks.exe /create` and for the PowerShell cmdlets
`Register-ScheduledTask` / `New-ScheduledTaskAction`. See [`detection.yml`](detection.yml).
For higher fidelity, enrich with Security **4698** and inspect the task's **action** — a task that
launches `powershell.exe`, `cmd.exe`, or something from a user-writable path is far more suspicious
than one pointing at a signed program in `Program Files`.

## False positives

Installers and legitimate admin automation create scheduled tasks constantly. Prioritise tasks
whose action is a script interpreter, runs from `%TEMP%` / `%APPDATA%`, or is created by a
non-admin user.

## Validate

Run the atomic, then open Security log → find **4698**, and read the embedded task XML to see the
command the task would run.
