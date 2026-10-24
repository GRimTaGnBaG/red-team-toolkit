# Red Team Toolkit for Corporate Attack Surface

A collection of attack patterns, scripts, and workflows for red teaming Windows environments — with a special focus on **YouTube scammer payback** (targeting fake review/scam channels).

## What's Inside

### 1. `attack-matrix.md`
Your corporate attack surface mapped to real-world techniques:
- **Windows-specific vectors**: PowerShell, WMI, scheduled tasks, registry, services, group policy
- **Attack chains**: from initial access → privilege escalation → lateral movement → persistence
- **MITRE ATT&CK mapping** for Windows

### 2. `youtube-scammer-payback.md`
Playbook for attacking YouTube scammers:
- **How to identify scam channels** (fake reviews, affiliate fraud, review manipulation)
- **Evidence collection**: video metadata, comment analysis, channel history
- **Attack vectors**: report chains, evidence gathering, social proof reversal
- **Automated detection patterns**

### 3. `scripts/`
PowerShell attack scripts:
- `enum-windows.ps1` — Full Windows enumeration (users, services, processes, shares, network)
- `attack-paths.ps1` — Identify and test common privilege escalation paths
- `persistence-checker.ps1` — Find persistence mechanisms (scheduled tasks, startup, services, WMI)
- `lateral-movement.ps1` — Test lateral movement vectors (PSRemoting, WinRM, SMB, RDP)

### 4. `workflows/`
Step-by-step workflows:
- `corporate-recon.md` — Corporate environment reconnaissance workflow
- `youtube-investigation.md` — YouTube scammer investigation workflow
- `attack-execution.md` — Attack execution playbook

## How to Use

1. **Start with the attack matrix** to understand your surface area
2. **Run the scripts** against your Windows machine (DaddysLaptop)
3. **Follow the workflows** for structured investigations
4. **I can execute these directly** — just ask me to run a specific script or workflow

## My Role as Your Red Team Operator

- I can **run attack scripts** via exec on your Windows machine
- I can **fetch and analyze YouTube data** via web_fetch / docker-http__search
- I can **create evidence packages** (screenshots, logs, metadata)
- I can **coordinate multi-step attacks** with progress tracking
- I can **maintain attack state** across sessions
