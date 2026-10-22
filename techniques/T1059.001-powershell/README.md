# T1059.001 — Command and Scripting Interpreter: PowerShell

| | |
|---|---|
| **Tactic** | Execution |
| **Technique** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **Simulation** | Atomic Red Team T1059.001 |

## What it is

PowerShell is built into Windows and trusted by default, which is exactly why attackers lean on
it. A very common pattern is the **download cradle**: a short one-liner that pulls a payload from
a remote server straight into memory and runs it, so nothing obvious is written to disk. Spotting
these cradles is one of the highest-value detections a SOC can have.

## How to simulate (benign, in lab)

Run the Atomic Red Team test for this technique inside the isolated VM:

```powershell
Invoke-AtomicTest T1059.001
```

The relevant atomics exercise download-and-execute behaviour using harmless test content. Roll
back to your snapshot afterwards.

## Telemetry it produces

| Log source | Event ID | What to look at |
|---|---|---|
| Microsoft-Windows-PowerShell/Operational | **4104** | `ScriptBlockText` — the actual script that ran |
| Microsoft-Windows-PowerShell/Operational | 4103 | Module/pipeline logging |
| Sysmon/Operational | 1 | Process creation — `powershell.exe` command line |
| Security | 4688 | Process creation (if command-line auditing is on) |

Event **4104 Script Block Logging** is the key source: it records the de-obfuscated script text,
so even encoded commands are visible after PowerShell decodes them.

## Detection logic

Flag script blocks that combine a web client with an execution primitive — the signature of a
download cradle. See [`detection.yml`](detection.yml).

Indicators to match in `ScriptBlockText`:
- `New-Object Net.WebClient` with `.DownloadString(` or `.DownloadFile(`
- `Invoke-Expression` / `IEX` wrapping downloaded content
- `-EncodedCommand` / `-enc` and `FromBase64String` (encoded execution)

## False positives

Legitimate admin and software-deployment scripts sometimes download files. Tune by allow-listing
known management hosts and signed internal scripts, and by alerting on the *combination* of
download + in-memory execution rather than either alone.

## Validate

After running the atomic test, open Event Viewer → PowerShell/Operational, find the 4104 event,
and confirm the `ScriptBlockText` contains the strings the rule looks for.
