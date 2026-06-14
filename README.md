# WinUpdate MSP Helper

Remote-run PowerShell helper for managing and troubleshooting Windows computers during MSP remote sessions.

The intended workflow is to open **PowerShell as Administrator** and run **one line**. The client runtime source is **GitHub raw only** because private Gitea requires login and blocks unauthenticated `curl`, `wget`, `Invoke-RestMethod`, and `WebClient` usage.

## One-line run command

Recommended elevated PowerShell one-liner with built-in fallback:

```powershell
$u='https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/menu.ps1'; $r='https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/README.md'; try { iex (irm $u) } catch { try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex ((New-Object Net.WebClient).DownloadString($u)) } catch { Write-Host "Failed to load menu. Open README: $r" -ForegroundColor Yellow; throw } }
```

Short form for newer PowerShell:

```powershell
iex (irm 'https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/menu.ps1')
```

Older Windows PowerShell fallback:

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main/menu.ps1'))
```

If the one-liner fails because of proxy, TLS, or PowerShell policy issues, open the README on GitHub and copy the fallback command.

## Design goals

- `menu.ps1` is the primary one-line admin entry point.
- `menu.ps1` and all helper scripts are loaded from GitHub raw HTTPS URLs and executed in memory.
- The menu and helper scripts do **not** save repo `.ps1` files to the client computer.
- Local persistence is limited to:
  - the actual system changes you choose to make, such as updates, repairs, installed packages, scheduled tasks, and reboots;
  - logs and JSON reports under `C:\ProgramData\WinUpdateMspHelper`.
- GitHub is the only public/client runtime source URL.
- The private Gitea mirror can still run `.gitea/workflows`, but those workflows clone/test/sync against GitHub so no client-facing command depends on the private Gitea host.

## Menu actions

The menu can run:

- Windows Update with no reboot.
- Windows Update with reboot only when a reboot is pending.
- Windows Update plus Winget application upgrades.
- Winget application upgrades only.
- Winget/App Installer install or repair.
- Disk health and free-space check.
- System snapshot report.
- Event log warning/error summary.
- Network/VPN connectivity check that asks for IPs or hostnames.
- Network adapter/IP snapshot.
- DISM/SFC repair, with optional Windows Update cache reset and DNS flush.
- Scheduled task installation for recurring remote-run updates/checks.

## Optional custom web mirror

GitHub raw is the default and recommended runtime source. For a separate public MSP-hosted mirror that does not require login and serves raw files directly, set `WINUPDATE_BASEURL` before launching the menu:

```powershell
$env:WINUPDATE_BASEURL='https://tools.example.com/winupdate'; $u="$env:WINUPDATE_BASEURL/menu.ps1"; $r="$env:WINUPDATE_BASEURL/README.md"; try { iex (irm $u) } catch { try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iex ((New-Object Net.WebClient).DownloadString($u)) } catch { Write-Host "Failed to load menu. Open README: $r" -ForegroundColor Yellow; throw } }
```

The URL must expose these raw files directly:

- `Common.ps1`
- `menu.ps1`
- `Invoke-WinUpdate.ps1`
- `Install-Winget.ps1`
- `DiskCheck.ps1`
- `Get-SystemSnapshot.ps1`
- `Get-EventSummary.ps1`
- `Get-NetworkInfo.ps1`
- `Test-NetworkConnectivity.ps1`
- `Repair-Windows.ps1`
- `Install-Task.ps1`
- `update-noreboot.ps1`
- `update-reboot.ps1`

## Scheduled task behavior

`Install-Task.ps1` creates a Windows Scheduled Task. The task action stores an encoded PowerShell command, not local `.ps1` files. When the task runs, it downloads `Common.ps1` and the selected helper script from the configured web URL into memory.

Available scheduled actions:

- `UpdateNoReboot`
- `UpdateIfNeeded`
- `UpdateWithWingetNoReboot`
- `WingetOnly`
- `SystemSnapshot`
- `DiskCheck`

Example remote-run scheduled task install:

```powershell
$env:WINUPDATE_BASEURL='https://raw.githubusercontent.com/TheTrueZeroTwo/winupdate/main'; iex (irm "$env:WINUPDATE_BASEURL/Common.ps1"); Invoke-WumRemoteScript -Name 'Install-Task.ps1' -Parameters @{ TaskAction = 'UpdateIfNeeded'; Frequency = 'Weekly'; At = '03:00'; DayOfWeek = 'Sunday'; Force = $true }
```

## Network/VPN checks

Use the menu option **Network/VPN connectivity check**. It asks for one or more IPs or hostnames, then checks:

- active adapters;
- VPN-like adapters;
- IP configuration;
- default routes;
- DNS servers;
- ping;
- TCP ports such as 443, 3389, 445, 53, and 80;
- optional trace route.

Good targets to enter during a remote MSP session include VPN gateway IP, firewall LAN IP, domain controller IP, file server IP, RDP host IP, printer IP, or a known public IP such as `1.1.1.1`.

## Logs and reports

Logs and generated JSON reports are stored here:

```text
C:\ProgramData\WinUpdateMspHelper\Logs
C:\ProgramData\WinUpdateMspHelper\Reports
```

Those files are intentionally persistent so a technician can review what happened after the remote session.

## Gitea Actions tests and Gitea wiki sync

This repo includes Gitea Actions workflows under `.gitea/workflows/`:

- `test.yml` validates the repo layout, checks the one-liner, checks script references, and enforces the remote-only rule that repo scripts are not cached locally.
- `sync-wiki.yml` automates the same wiki process you would run manually: clone the Gitea wiki repo, `rsync` the local `wiki/` folder into it, commit changes, and push.

The client/runtime scripts still use GitHub raw URLs only. The private Gitea URL is used only by the Gitea Actions wiki automation and optional local wiki sync helper.

For wiki sync in Gitea Actions, create these repo secrets if the runner does not already have wiki push credentials:

- `WIKI_TOKEN` — token/password with write access to the Gitea wiki repo.
- `WIKI_USER` — optional username for the token. If omitted, the workflow uses the Actions actor.

The workflow target is:

```text
https://gitthegit.zerotwo.tech/ZeroTwo/winupdate.wiki.git
```

Local manual sync helper:

```bash
./tools/Sync-GiteaWiki.sh
```

That helper does the same core flow:

```bash
git clone https://gitthegit.zerotwo.tech/ZeroTwo/winupdate.wiki.git WinUpdate.wiki
rsync -a --delete wiki/ WinUpdate.wiki/
cd WinUpdate.wiki
git add -A
git commit -m "Update WinUpdate wiki pages"
git push
```

## Wiki source

The `wiki/` directory is the editable source for the wiki. Update those markdown files in the main repo. The Gitea workflow copies them into the Gitea wiki repo automatically.

## Notes for MSP use

Run this only from a trusted source you control. A one-line web execution helper is convenient for remote support, but the raw web source is the code being executed on the client.

For Windows Update, this uses the `PSWindowsUpdate` PowerShell module. For third-party and Microsoft Store-style app updates, it uses `winget` when available.
