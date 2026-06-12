# WinUpdate MSP Helper Wiki

WinUpdate MSP Helper is a remote-run PowerShell toolkit for MSP technicians who are already connected to a Windows computer through a remote support session.

The normal workflow is:

1. Open PowerShell as Administrator.
2. Paste the one-line menu command.
3. Pick the troubleshooting or update action from `menu.ps1`.
4. Review logs and JSON reports under `C:\ProgramData\WinUpdateMspHelper`.

The repo is designed so that scripts execute from a trusted raw HTTPS source in memory. The client computer should not receive downloaded copies of the repo `.ps1` files.

Use the sidebar pages for one-line run commands, menu behavior, scheduled tasks, networking/VPN checks, and CI/wiki automation.
