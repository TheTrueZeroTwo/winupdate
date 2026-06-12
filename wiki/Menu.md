# Menu

`menu.ps1` is the interactive entry point for remote MSP work.

Main options include:

- Windows Update, no reboot.
- Windows Update, reboot only if needed.
- Windows Update plus Winget app upgrades.
- Winget app upgrades only.
- Install or repair Winget/App Installer.
- Disk health and free-space check.
- System snapshot report.
- Event log error summary.
- Network/VPN connectivity check.
- Network adapter/IP snapshot.
- DISM/SFC repair.
- Install a scheduled task.
- Open local log folder.
- Show one-line commands and fallback help.

The generated `Menu-Options` page is updated automatically from `menu.ps1` when the wiki workflow runs.
