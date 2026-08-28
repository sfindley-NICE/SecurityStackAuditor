# Endpoint Security Stack Collector

Collects a snapshot of what's running on your machine — processes, CPU/RAM usage,
security tooling (EDR/AV/VPN/DLP/PAM/MDM), registered AV/Firewall products, and
VPN network adapters — and writes it to a single JSON file you can hand to Claude
for analysis.

## Run it

1. Download `Collect-SecurityStackAudit.ps1`.
2. Open PowerShell (Run as Administrator recommended, not required) in the folder
   you saved it to.
3. Run:

   ```powershell
   .\Collect-SecurityStackAudit.ps1
   ```

   If you get an execution-policy error, run it this way instead (doesn't change
   your system-wide policy):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Collect-SecurityStackAudit.ps1
   ```

4. It takes about 30 seconds (it's live-sampling CPU usage). When it's done, it
   writes two files to your Desktop by default:
   - `SecurityStackAudit-<hostname>-<timestamp>.json` — give this to Claude
   - `SecurityStackAudit-<hostname>-<timestamp>-Processes.csv` — for a quick
     spreadsheet look yourself, optional

## Analyze it with Claude

Upload or paste the JSON file to Claude and ask something like:

> "Analyze this endpoint security stack audit — what overlaps, redundancies, or
> performance risks do you see, and what should I raise with IT?"

Claude can compare your stack against others on the team if you collect a few
and share them together.

## Useful options

```powershell
# Longer, steadier sample
.\Collect-SecurityStackAudit.ps1 -SampleSeconds 60

# Every process, not just security-flagged + top resource users
.\Collect-SecurityStackAudit.ps1 -IncludeAllProcesses

# Custom output location
.\Collect-SecurityStackAudit.ps1 -OutputDir C:\Temp

# Quiet run (no progress messages)
.\Collect-SecurityStackAudit.ps1 -Quiet
```

Run `Get-Help .\Collect-SecurityStackAudit.ps1 -Full` for the complete parameter
list and notes.

## What it does and doesn't collect

**Collects:** process names, file paths, publisher/signer info, CPU and RAM
usage, system specs, registered AV/Firewall products, VPN-related network
adapters, security-related service states.

**Does not collect:** file contents, browser history, documents, credentials,
or command-line arguments — except that command lines for processes *already
identified as security tooling* are captured only if you explicitly pass
`-IncludeCommandLines`, and never for your own applications.

As with any script someone hands you, it's worth a skim before you run it —
it's about 350 lines and heavily commented.

## Sharing your results

The JSON only contains process/publisher/performance metadata, not personal
file content — but it does include your hostname, username, and installed
security tooling. Share it the way you'd share any internal diagnostic output
(e.g., in an internal channel or ticket), not somewhere public.
