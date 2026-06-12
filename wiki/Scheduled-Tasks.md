# Scheduled Tasks

`Install-Task.ps1` creates a Windows Scheduled Task that runs one of the supported remote actions.

Supported actions:

- `UpdateNoReboot`
- `UpdateIfNeeded`
- `UpdateWithWingetNoReboot`
- `WingetOnly`
- `SystemSnapshot`
- `DiskCheck`

The task stores an encoded PowerShell command. At runtime, that command loads `Common.ps1` and then loads the selected action script from the configured web source.

Run as `SYSTEM` for update and maintenance tasks. Run as the current interactive user when you specifically need user-context behavior, especially some Winget scenarios.
