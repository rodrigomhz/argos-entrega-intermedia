# Argos

> Local malware analysis sandbox — offline alternative to any.run / CAPE

Argos is a self-hosted malware analysis platform that runs entirely offline. **No samples leave your machine.**

## What it does

- **Static analysis** — file type, PE headers, imports table, strings, entropy, packer detection
- **Dynamic analysis** — isolated VM sandbox via VMware/vmrun, behavior capture with Noriben + CAPEsolo
- **Behavior report** — process tree, network calls, file system & registry changes
- **Ensemble scorer** — local ML classifier + signature rules → verdict
- **VirusTotal-style interface** — no uploads, no external dependencies

## Why offline

Hard requirement: malware samples must not be submitted to external services.  
Argos replaces any.run / VirusTotal / CAPE for lab environments where network egress is locked down or sample confidentiality is required.

## Architecture

```
sample ──► static engine ──► PE parser / strings / entropy / imports
        │
        └─► dynamic engine ──► vmrun sandbox ──► Noriben / CAPEsolo
                                                         │
                                         behavior report ◄─────────────┘
                                                │
                                    ensemble scorer ──► verdict
```

## Stack

- **Host**: Windows 10/11
- **Sandbox**: VMware Workstation Pro + vmrun
- **Behavior capture**: Noriben (procmon-based), CAPEsolo
- **Static**: Python 3.10+, pefile, YARA
- **Backend**: Node.js
- **Classifier**: local model, no cloud inference

## Status

Active development. Static analysis + dynamic pipeline functional. Ensemble scorer in progress.

## Requirements

- VMware Workstation Pro with a clean Windows VM snapshot
- Python 3.10+
- Node.js 18+

---

*Part of a personal malware lab built for learning advanced malware analysis and detection engineering.*
